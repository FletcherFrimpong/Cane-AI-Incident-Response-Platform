"""
Guard rails between what the LLM says and what the platform does.

The model's reply is untrusted: it is produced from log content an attacker can
write, and it may simply be wrong. This module is pure (no I/O) so its rules are
easy to test. It does three things:

1. `parse_triage_output` - strictly validates the reply's shape and ranges.
2. `observed_entities`  - collects the IPs / hosts / accounts / URLs / hashes that
                          actually occur in the incident's evidence.
3. `plan_action`        - decides, per recommended action, whether it may run
                          automatically, must wait for an analyst, or is dropped.

The model can only ever *suggest*. Whether something runs unattended is decided
here from configuration and evidence, never from the model's say-so alone.
"""

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from app.services.action_service import ACTION_PARAM_KEYS

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Actions the AI may propose. Reversals (enable_account, release_host) and free-form
# queries (run_kql_query) are analyst-only: nothing in a log should be able to
# get an account re-enabled or a host released.
AI_PROPOSABLE_ACTIONS = {
    "block_ip": "ips",
    "block_url": "urls",
    "block_file_hash": "file_hashes",
    "isolate_host": "hosts",
    "run_av_scan": "hosts",
    "disable_account": "users",
    "revoke_sessions": "users",
    "force_password_reset": "users",
    "purge_email": "message_ids",
}

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_IP_FIELDS = (
    "SourceIP", "DestinationIP", "IPAddress", "IpAddress", "ClientIP", "CIp", "CallerIpAddress",
    "RemoteIP", "SenderIPv4", "SourceIpAddress", "ClientIPAddress",
)
_USER_FIELDS = (
    "UserPrincipalName", "Account", "TargetUserName", "SubjectUserName", "UserId",
    "RecipientEmailAddress", "AccountUpn", "TargetAccount",
)
_HOST_FIELDS = ("Computer", "CompromisedEntity", "DeviceName", "HostName", "Workstation")
_URL_FIELDS = ("Url", "RemoteUrl", "FileOriginUrl", "ClickUrl", "RequestURL")
_HASH_FIELDS = (
    "FileHash", "SHA256", "SHA1", "MD5", "FileHashSha256", "FileHashSha1", "FileHashMd5",
    "InitiatingProcessSHA256", "InitiatingProcessSHA1",
)


class TriageParseError(ValueError):
    """The model's reply could not be used as a triage assessment."""


class RecommendedAction(BaseModel):
    action: str
    target: str | None = None
    priority: str = "medium"
    reason: str = ""
    can_auto_execute: bool = False

    @field_validator("action")
    @classmethod
    def _normalise_action(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("target", mode="before")
    @classmethod
    def _target_to_str(cls, v: Any) -> str | None:
        if v is None:
            return None
        text = str(v).strip()
        return text or None


class TriageOutput(BaseModel):
    severity: Literal["critical", "high", "medium", "low", "info"]
    attack_type: str | None = None
    confidence_score: float = Field(ge=0.0, le=1.0)
    summary: str
    kill_chain_phase: str | None = None
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    indicators_of_compromise: dict[str, list[str]] = {}
    recommended_actions: list[RecommendedAction] = []
    # Absent means "we don't know", which must fail safe: a person looks at it.
    requires_human_review: bool = True
    human_review_reason: str | None = None
    suggested_playbook: str | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def _lower(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("attack_type", "suggested_playbook", "kill_chain_phase", mode="before")
    @classmethod
    def _null_strings(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip().lower() in ("", "null", "none", "n/a"):
            return None
        return v

    @field_validator("mitre_tactics", "mitre_techniques", mode="before")
    @classmethod
    def _list_of_str(cls, v: Any) -> Any:
        if v is None:
            return []
        if isinstance(v, list):
            return [str(item) for item in v if item is not None]
        return v

    @field_validator("indicators_of_compromise", mode="before")
    @classmethod
    def _iocs(cls, v: Any) -> Any:
        if not isinstance(v, dict):
            return {}
        return {str(k): [str(i) for i in items] for k, items in v.items() if isinstance(items, list)}

    @field_validator("recommended_actions", mode="before")
    @classmethod
    def _only_objects(cls, v: Any) -> Any:
        if not isinstance(v, list):
            return []
        return [item for item in v if isinstance(item, dict) and item.get("action")]


def extract_json_object(text: str) -> dict:
    """Pull the JSON object out of an LLM reply (tolerates code fences and stray prose)."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = "\n".join(line for line in text.split("\n") if not line.strip().startswith("```"))
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}") + 1
        if start < 0 or end <= start:
            raise TriageParseError("Reply contained no JSON object")
        try:
            parsed = json.loads(text[start:end])
        except json.JSONDecodeError as e:
            raise TriageParseError(f"Reply was not valid JSON: {e.msg}")
    if not isinstance(parsed, dict):
        raise TriageParseError("Reply was JSON but not an object")
    return parsed


def parse_triage_output(text: str) -> TriageOutput:
    """Validate an LLM triage reply. Raises TriageParseError if it cannot be trusted
    as an assessment (wrong shape, confidence outside 0-1, unknown severity...)."""
    data = extract_json_object(text)
    try:
        return TriageOutput.model_validate(data)
    except ValidationError as e:
        problems = "; ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()[:5])
        raise TriageParseError(f"Reply did not match the triage schema ({problems})")


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _norm_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def observed_entities(events_data: list[dict]) -> dict:
    """Every entity that literally appears in the incident's events, lower-cased.
    An AI-recommended action may only target something found here."""
    found: dict = {"ips": set(), "hosts": set(), "users": set(), "urls": set(), "file_hashes": set(),
                   "message_ids": set(), "message_recipients": {}}

    def add(kind: str, value: Any):
        if isinstance(value, str) and value.strip():
            found[kind].add(value.strip().lower())

    for event in events_data:
        raw = event.get("raw_data") or {}
        for value in [event.get("source_ip"), event.get("destination_ip"), *(raw.get(f) for f in _IP_FIELDS)]:
            ip = _norm_ip(value) if value else None
            if ip:
                found["ips"].add(ip)
        add("hosts", event.get("host"))
        add("users", event.get("user_identity"))
        for f in _HOST_FIELDS:
            add("hosts", raw.get(f))
        for f in _USER_FIELDS:
            add("users", raw.get(f))
        for f in _URL_FIELDS:
            add("urls", raw.get(f))
        message_id = raw.get("InternetMessageId")
        if isinstance(message_id, str) and message_id.strip():
            key = message_id.strip().lower()
            found["message_ids"].add(key)
            recipient = raw.get("RecipientEmailAddress")
            if isinstance(recipient, str) and "@" in recipient:
                found["message_recipients"].setdefault(key, set()).add(recipient.strip().lower())
        for f in _HASH_FIELDS:
            value = raw.get(f)
            if isinstance(value, str) and _HASH_RE.match(value.strip()):
                found["file_hashes"].add(value.strip().lower())
        entities = raw.get("Entities")
        if isinstance(entities, list):
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                ip = _norm_ip(entity.get("Address")) if entity.get("Address") else None
                if ip:
                    found["ips"].add(ip)
                add("hosts", entity.get("HostName"))
                add("users", entity.get("Name"))
                add("users", entity.get("UserPrincipalName"))
                add("urls", entity.get("Url"))
    return found


@dataclass
class ActionPlan:
    action_type: str
    target: str | None
    params: dict | None
    disposition: Literal["auto", "queue", "skip"]
    reason: str

    def as_dict(self) -> dict:
        return {"action": self.action_type, "target": self.target,
                "disposition": self.disposition, "reason": self.reason}


def plan_action(
    rec: RecommendedAction,
    observed: dict,
    confidence: float,
    requires_human_review: bool,
    auto_types: list[str],
    threshold: float,
    allow_auto: bool = True,
) -> ActionPlan:
    """Decide what happens to one AI-recommended action.

    skip  - not something the AI may propose, or its target is not in the evidence
    queue - created as pending; an analyst approves or rejects it
    auto  - executed without a person; only when every one of these holds:
            the type is on the configured allow-list, the model flagged it
            auto-executable, the model did not ask for human review, confidence is at
            or above the threshold, and the caller permits automation at all.
    """
    action = rec.action
    kind = AI_PROPOSABLE_ACTIONS.get(action)
    if kind is None:
        return ActionPlan(action, rec.target, None, "skip", "not an action the AI is allowed to propose")
    if not rec.target:
        return ActionPlan(action, None, None, "skip", "no target given")

    target = rec.target.strip()
    if kind == "ips":
        ip = _norm_ip(target)
        if ip is None:
            return ActionPlan(action, target, None, "skip", "target is not a valid IP address")
        if not _is_public_ip(ip):
            return ActionPlan(action, target, None, "skip", "refusing to block a private or reserved address")
        if ip not in observed["ips"]:
            return ActionPlan(action, target, None, "skip", "target IP does not appear in the incident's events")
        target = ip
    elif target.lower() not in observed[kind]:
        return ActionPlan(action, target, None, "skip", "target does not appear in the incident's events")
    if kind == "hosts" and (" " in target or len(target) > 253):
        # Free text that ended up in a host field ("Multiple Systems") is not a machine.
        return ActionPlan(action, target, None, "skip", "not a hostname")
    if kind == "users" and "@" not in target:
        # Logs are full of local and built-in accounts (SYSTEM, admin, svc_backup).
        # Identity actions go to a directory, which only knows sign-in names.
        return ActionPlan(action, target, None, "skip", "not a directory sign-in name (no @domain)")

    params = {ACTION_PARAM_KEYS[action]: target}
    if action == "purge_email":
        recipients = sorted(observed.get("message_recipients", {}).get(target.lower(), set()))
        if not recipients:
            return ActionPlan(action, target, None, "skip", "no recipient mailboxes are recorded for that message")
        params["recipients"] = ",".join(recipients)

    if not allow_auto:
        return ActionPlan(action, target, params, "queue", "analyst-triggered triage never auto-executes")
    if action not in auto_types:
        return ActionPlan(action, target, params, "queue", "this action type always needs analyst approval")
    if not rec.can_auto_execute:
        return ActionPlan(action, target, params, "queue", "model did not mark it safe to auto-execute")
    if requires_human_review:
        return ActionPlan(action, target, params, "queue", "model asked for human review")
    if confidence < threshold:
        return ActionPlan(action, target, params, "queue",
                          f"confidence {confidence:.2f} is below the {threshold:.2f} threshold")
    return ActionPlan(action, target, params, "auto",
                      f"allow-listed action, confidence {confidence:.2f} >= {threshold:.2f}")
