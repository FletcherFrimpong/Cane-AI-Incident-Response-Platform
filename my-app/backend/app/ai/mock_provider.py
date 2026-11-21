"""Offline stand-in for an LLM, for local development and pipeline tests.

It is NOT an AI model. It applies a handful of fixed rules to the events in the
prompt and returns a reply in the triage schema, so the whole pipeline
(triage -> guard -> action queue -> playbook) can be exercised with no API key and
no cost. Selected with CANE_AUTO_TRIAGE_PROVIDER=mock, and only when CANE_DEBUG=true.
Every analysis it produces is labelled provider "mock".
"""

import ipaddress
import json
import re

from app.ai.provider_base import LLMResponse
from app.services.correlation import ATTACK_INDICATORS

_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_PLAYBOOKS = {"ransomware", "phishing", "data_exfiltration", "ddos", "unauthorized_access", "malware", "insider_threat"}


def _events_from_prompt(prompt: str) -> list[dict]:
    match = re.search(r"## Log Events[^\n]*\n```json\n(.*?)\n```", prompt, re.S)
    if not match:
        return []
    try:
        events = json.loads(match.group(1))
        return events if isinstance(events, list) else []
    except json.JSONDecodeError:
        return []


def _public(ip) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


class MockProvider:
    provider_name = "mock"

    async def analyze(self, system_prompt: str, user_prompt: str, model: str | None = None,
                      temperature: float = 0.1, max_tokens: int = 4096) -> LLMResponse:
        return await self.analyze_with_json(system_prompt, user_prompt, model, temperature, max_tokens)

    async def analyze_with_json(self, system_prompt: str, user_prompt: str, model: str | None = None,
                                temperature: float = 0.1, max_tokens: int = 4096) -> LLMResponse:
        events = _events_from_prompt(user_prompt)
        text = " ".join(json.dumps(e).lower() for e in events)
        severity = max((str(e.get("severity", "info")) for e in events), key=lambda s: _RANK.get(s, 0), default="info")
        attack = next((name for name, words in ATTACK_INDICATORS.items() if any(w in text for w in words)), None)

        ips = sorted({str(e[k]) for e in events for k in ("source_ip", "destination_ip") if e.get(k) and _public(e[k])})
        hosts = sorted({e["host"] for e in events if e.get("host")})
        users = sorted({e["user_identity"] for e in events if e.get("user_identity")})

        serious = _RANK.get(severity, 0) >= 4
        actions = [{"action": "block_ip", "target": ip, "priority": "immediate" if serious else "medium",
                    "reason": "External address involved in the suspicious activity", "can_auto_execute": serious}
                   for ip in ips[:3]]
        if serious:
            actions += [{"action": "isolate_host", "target": h, "priority": "high",
                         "reason": "Host shows signs of compromise", "can_auto_execute": False} for h in hosts[:2]]
            actions += [{"action": "revoke_sessions", "target": u, "priority": "high",
                         "reason": "Account was active during the attack window", "can_auto_execute": False}
                        for u in users[:2]]

        reply = {
            "severity": severity,
            "attack_type": attack,
            "confidence_score": 0.96 if severity == "critical" and attack else (0.8 if serious else 0.6),
            "summary": (f"[Mock analysis - rule based, not an AI model] {len(events)} events reviewed; "
                        f"highest severity {severity}"
                        + (f", pattern consistent with {attack.replace('_', ' ')}" if attack else "")
                        + (f". External address(es): {', '.join(ips[:3])}." if ips else ".")),
            "kill_chain_phase": "actions_on_objectives" if attack in ("ransomware", "data_exfiltration") else None,
            "mitre_tactics": ["Impact", "Execution"] if attack == "ransomware" else (["Initial Access"] if attack else []),
            "mitre_techniques": ["T1486", "T1059"] if attack == "ransomware" else (["T1566"] if attack == "phishing" else []),
            "indicators_of_compromise": {"ips": ips, "domains": [], "file_hashes": [], "emails": []},
            "recommended_actions": actions,
            "requires_human_review": not (severity == "critical" and attack),
            "human_review_reason": None if severity == "critical" and attack else "Rule-based mock analysis: verify manually",
            "suggested_playbook": attack if attack in _PLAYBOOKS else None,
        }
        return LLMResponse(content=json.dumps(reply), model="mock-rules-v1", provider="mock",
                           prompt_tokens=0, completion_tokens=0, total_tokens=0)
