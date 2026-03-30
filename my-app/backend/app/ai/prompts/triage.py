"""Prompt templates for AI-powered incident triage."""

import json

TRIAGE_SYSTEM_PROMPT = """You are an expert cybersecurity incident response analyst working in a Security Operations Center (SOC). Your role is to analyze security log events and provide precise triage assessments.

You follow the NIST 800-61 Computer Security Incident Handling Guide and MITRE ATT&CK framework.

When analyzing security events, you must:
1. Classify the severity (critical, high, medium, low, info)
2. Identify the attack type if applicable
3. Map to MITRE ATT&CK tactics and techniques
4. Assess confidence in your analysis (0.0 to 1.0)
5. Provide a clear summary of what happened
6. Recommend specific response actions with actionable targets (IPs, hostnames, user accounts)
7. Determine if this requires immediate human intervention

If threat intelligence enrichment data is provided, factor it heavily into your analysis:
- High VirusTotal malicious counts or high AbuseIPDB abuse confidence scores should increase your confidence and may warrant raising severity.
- Known-malicious IPs, hashes, or domains are strong indicators — recommend blocking them with can_auto_execute=true.
- Cross-reference enrichment findings with log event patterns for stronger correlations.

Always respond with a valid JSON object matching the exact schema specified."""


def build_triage_prompt(log_events: list[dict], incident_context: dict | None = None, enrichment_data: dict | None = None) -> str:
    """Build the user prompt for triage analysis."""

    events_summary = []
    for i, event in enumerate(log_events[:20]):  # Limit to 20 events to control token usage
        summary = {
            "index": i,
            "log_type": event.get("log_type", "unknown"),
            "time_generated": str(event.get("time_generated", "")),
            "severity": event.get("severity", "info"),
            "summary": event.get("summary", ""),
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
            "user_identity": event.get("user_identity"),
            "host": event.get("host"),
            "correlation_id": event.get("correlation_id"),
        }
        # Include key raw data fields for richer analysis
        raw = event.get("raw_data", {})
        for field in ["AlertName", "DisplayName", "Description", "ThreatTypes",
                      "EventID", "Activity", "DeviceAction", "DeviceVendor",
                      "CommandLine", "CallerProcessName", "Name", "Url"]:
            if field in raw:
                summary[field] = str(raw[field])[:500]
        events_summary.append(summary)

    prompt = f"""Analyze the following {len(events_summary)} security log events and provide a triage assessment.

## Log Events
```json
{json.dumps(events_summary, indent=2, default=str)}
```
"""

    if incident_context:
        prompt += f"""
## Incident Context
```json
{json.dumps(incident_context, indent=2, default=str)}
```
"""

    if enrichment_data and any(enrichment_data.get(k) for k in ["ip_results", "hash_results", "domain_results", "url_results"]):
        prompt += f"""
## Threat Intelligence Enrichment
The following IOCs from the log events were queried against threat intelligence platforms ({', '.join(enrichment_data.get('enrichment_sources', []))}).
Use this data to inform your severity assessment, confidence score, and recommended actions.
```json
{json.dumps({k: v for k, v in enrichment_data.items() if k != 'enrichment_sources' and v}, indent=2, default=str)}
```
"""

    prompt += """
## Required Response Format
Respond with a JSON object containing exactly these fields:
```json
{
    "severity": "critical|high|medium|low|info",
    "attack_type": "string or null",
    "confidence_score": 0.0-1.0,
    "summary": "Clear 2-3 sentence description of what happened",
    "kill_chain_phase": "reconnaissance|weaponization|delivery|exploitation|installation|command_and_control|actions_on_objectives|null",
    "mitre_tactics": ["list of MITRE ATT&CK tactic names"],
    "mitre_techniques": ["list of MITRE ATT&CK technique IDs like T1566.001"],
    "indicators_of_compromise": {
        "ips": ["malicious IPs found"],
        "domains": ["malicious domains found"],
        "file_hashes": ["malicious hashes found"],
        "emails": ["malicious email addresses found"]
    },
    "recommended_actions": [
        {
            "action": "action_type (block_ip, disable_account, quarantine_email, isolate_host, etc.)",
            "target": "specific target (IP, email, hostname)",
            "priority": "immediate|high|medium|low",
            "reason": "why this action is recommended",
            "can_auto_execute": true/false
        }
    ],
    "requires_human_review": true/false,
    "human_review_reason": "why human review is needed, or null",
    "suggested_playbook": "ransomware|phishing|data_exfiltration|ddos|unauthorized_access|malware|insider_threat|null"
}
```"""

    return prompt


CORRELATION_SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in threat correlation and attack chain reconstruction.

Given a set of correlated security events (linked by a common correlation ID), reconstruct the attack narrative - what happened, in what order, and what the attacker's objectives were.

Map the entire attack to the MITRE ATT&CK kill chain and provide a timeline of events.

Always respond with valid JSON."""


def build_correlation_prompt(events: list[dict]) -> str:
    """Build prompt for correlating events into an attack narrative."""

    events_data = []
    for event in events[:30]:  # Limit to 30 events
        entry = {
            "log_type": event.get("log_type", ""),
            "time_generated": str(event.get("time_generated", "")),
            "severity": event.get("severity", ""),
            "summary": event.get("summary", ""),
            "source_ip": event.get("source_ip"),
            "user_identity": event.get("user_identity"),
            "host": event.get("host"),
        }
        raw = event.get("raw_data", {})
        for field in ["AlertName", "Description", "ThreatTypes", "EventID",
                      "CommandLine", "DeviceAction", "Name"]:
            if field in raw:
                entry[field] = str(raw[field])[:300]
        events_data.append(entry)

    return f"""Analyze these {len(events_data)} correlated security events and reconstruct the attack narrative.

## Correlated Events
```json
{json.dumps(events_data, indent=2, default=str)}
```

## Required Response Format
```json
{{
    "attack_narrative": "Detailed description of the full attack chain",
    "attack_type": "ransomware|phishing|data_exfiltration|ddos|brute_force|malware|apt|insider_threat",
    "severity": "critical|high|medium|low",
    "confidence": 0.0-1.0,
    "timeline": [
        {{
            "time": "timestamp",
            "event": "what happened",
            "mitre_tactic": "tactic name",
            "mitre_technique": "technique ID"
        }}
    ],
    "threat_actors": {{
        "source_ips": [],
        "source_countries": [],
        "attributed_group": "APT name or null"
    }},
    "impacted_assets": {{
        "hosts": [],
        "users": [],
        "data": "description of data at risk"
    }},
    "recommended_playbook": "playbook name",
    "immediate_actions": ["list of urgent actions needed"]
}}
```"""


RECOMMENDATION_SYSTEM_PROMPT = """You are a senior SOC analyst providing actionable recommendations for incident response.

Based on the incident analysis and available playbooks, recommend specific steps the analyst should take. Be precise and actionable - each recommendation should be something the analyst can do immediately.

Consider the NIST 800-61 framework phases: Detection & Analysis → Containment → Eradication → Recovery → Post-Incident.

Always respond with valid JSON."""


def build_recommendation_prompt(incident: dict, analysis: dict, available_playbooks: list[dict]) -> str:
    """Build prompt for action recommendations."""

    return f"""Based on this incident and AI analysis, provide specific response recommendations.

## Incident
```json
{json.dumps(incident, indent=2, default=str)}
```

## AI Analysis
```json
{json.dumps(analysis, indent=2, default=str)}
```

## Available Playbooks
```json
{json.dumps(available_playbooks, indent=2, default=str)}
```

## Required Response Format
```json
{{
    "recommended_playbook_id": "UUID of best matching playbook or null",
    "playbook_match_confidence": 0.0-1.0,
    "steps": [
        {{
            "order": 1,
            "phase": "detection_analysis|containment|eradication|recovery|post_incident",
            "action": "specific action description",
            "is_automated": true/false,
            "auto_action_type": "block_ip|disable_account|quarantine_email|isolate_host|null",
            "auto_action_params": {{}},
            "requires_approval": true/false,
            "urgency": "immediate|high|medium|low"
        }}
    ],
    "analyst_guidance": "Summary guidance for the analyst on how to handle this incident"
}}
```"""
