"""Prompt template for matching incidents to playbooks."""

import json

PLAYBOOK_MATCH_SYSTEM_PROMPT = """You are a cybersecurity playbook matching engine. Given an incident description and a list of available playbooks, determine which playbook best fits the incident.

Consider:
1. Attack type alignment
2. Severity match
3. MITRE ATT&CK tactics overlap
4. Specific indicators in the incident

Always respond with valid JSON."""


def build_playbook_match_prompt(incident: dict, playbooks: list[dict]) -> str:
    return f"""Match this incident to the best playbook.

## Incident
```json
{json.dumps(incident, indent=2, default=str)}
```

## Available Playbooks
```json
{json.dumps(playbooks, indent=2, default=str)}
```

## Required Response Format
```json
{{
    "matched_playbook_id": "UUID or null",
    "confidence": 0.0-1.0,
    "reasoning": "why this playbook is the best match",
    "customizations": ["any modifications to the playbook steps for this specific incident"]
}}
```"""
