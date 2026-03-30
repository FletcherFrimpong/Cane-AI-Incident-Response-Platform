"""
Triage service: orchestrates AI analysis of security incidents.
This is the core business logic that ties log correlation, AI analysis,
incident creation, and playbook matching together.
"""

import json
import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident, IncidentTimeline, IncidentSeverity, IncidentStatus
from app.models.log_event import LogEvent
from app.models.triage import AiAnalysis
from app.models.playbook import Playbook
from app.ai.provider_factory import get_provider_for_user, get_system_provider
from app.ai.prompts.triage import (
    TRIAGE_SYSTEM_PROMPT,
    build_triage_prompt,
    CORRELATION_SYSTEM_PROMPT,
    build_correlation_prompt,
    RECOMMENDATION_SYSTEM_PROMPT,
    build_recommendation_prompt,
)
from app.exceptions import NotFoundError

import uuid as uuid_mod

logger = logging.getLogger("cane_ai.triage")

# Maps AI-recommended action types to their expected parameter key names
_ACTION_PARAM_KEYS = {
    "block_ip": "ip_address",
    "block_url": "url",
    "block_file_hash": "file_hash",
    "isolate_host": "machine_id",
    "release_host": "machine_id",
    "run_av_scan": "machine_id",
    "disable_account": "user_principal_name",
    "enable_account": "user_principal_name",
    "revoke_sessions": "user_principal_name",
    "force_password_reset": "user_principal_name",
    "quarantine_email": "file_hash",
}


def _action_param_key(action_type: str) -> str:
    return _ACTION_PARAM_KEYS.get(action_type, "target")


def _safe_parse_json(text: str) -> dict:
    """Parse JSON from LLM response, handling markdown code blocks."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last lines (code block markers)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
        return {"error": "Failed to parse AI response", "raw": text[:500]}


async def triage_incident(
    db: AsyncSession,
    incident_id: uuid_mod.UUID,
    user_id: uuid_mod.UUID,
    provider_name: str | None = None,
    model: str | None = None,
) -> AiAnalysis:
    """Run AI triage analysis on an incident."""

    # Get the incident
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    # Get associated log events
    result = await db.execute(
        select(LogEvent)
        .where(LogEvent.incident_id == incident_id)
        .order_by(LogEvent.time_generated.asc())
    )
    log_events = result.scalars().all()

    # If no log events linked, try by correlation_id
    if not log_events and incident.correlation_id:
        result = await db.execute(
            select(LogEvent)
            .where(LogEvent.correlation_id == incident.correlation_id)
            .order_by(LogEvent.time_generated.asc())
        )
        log_events = result.scalars().all()

    if not log_events:
        raise NotFoundError("No log events found for this incident")

    # Prepare event data for the prompt
    events_data = []
    for event in log_events:
        events_data.append({
            "log_type": event.log_type,
            "time_generated": str(event.time_generated),
            "severity": event.severity,
            "summary": event.summary,
            "source_ip": str(event.source_ip) if event.source_ip else None,
            "destination_ip": str(event.destination_ip) if event.destination_ip else None,
            "user_identity": event.user_identity,
            "host": event.host,
            "correlation_id": event.correlation_id,
            "raw_data": event.raw_data,
        })

    incident_context = {
        "id": str(incident.id),
        "title": incident.title,
        "current_severity": incident.severity.value if incident.severity else "unknown",
        "attack_type": incident.attack_type,
        "status": incident.status.value if incident.status else "new",
    }

    # Get LLM provider
    provider = await get_provider_for_user(db, user_id, provider_name)

    # Run triage analysis
    prompt = build_triage_prompt(events_data, incident_context)
    llm_response = await provider.analyze_with_json(
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        user_prompt=prompt,
        model=model,
    )

    analysis_output = _safe_parse_json(llm_response.content)

    # Update incident based on AI analysis
    if "severity" in analysis_output:
        try:
            incident.severity = IncidentSeverity(analysis_output["severity"])
        except ValueError:
            pass
    if "attack_type" in analysis_output and analysis_output["attack_type"]:
        incident.attack_type = analysis_output["attack_type"]
    if "confidence_score" in analysis_output:
        incident.confidence_score = analysis_output["confidence_score"]
    if "mitre_tactics" in analysis_output:
        incident.mitre_tactics = analysis_output["mitre_tactics"]
    if "mitre_techniques" in analysis_output:
        incident.mitre_techniques = analysis_output["mitre_techniques"]

    # If requires human review, set status
    if analysis_output.get("requires_human_review", False):
        incident.status = IncidentStatus.AWAITING_ANALYST
    elif incident.status == IncidentStatus.NEW:
        incident.status = IncidentStatus.TRIAGING

    # Store AI analysis
    ai_analysis = AiAnalysis(
        incident_id=incident.id,
        provider=llm_response.provider,
        model=llm_response.model,
        prompt_tokens=llm_response.prompt_tokens,
        completion_tokens=llm_response.completion_tokens,
        analysis_type="triage",
        input_summary=f"Triage of {len(log_events)} events for incident {incident.title}",
        output=analysis_output,
        confidence_score=analysis_output.get("confidence_score"),
        recommended_actions=analysis_output.get("recommended_actions"),
    )

    # Try to match a playbook
    suggested = analysis_output.get("suggested_playbook")
    if suggested:
        result = await db.execute(
            select(Playbook).where(
                Playbook.is_active == True,
                Playbook.attack_types.contains([suggested]),
            )
        )
        playbook = result.scalar_one_or_none()
        if playbook:
            ai_analysis.recommended_playbook_id = playbook.id
            incident.playbook_id = playbook.id
            incident.current_playbook_step = 0

    db.add(ai_analysis)

    # Add timeline entry
    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="ai_analysis",
        actor="ai",
        description=f"AI triage completed: {analysis_output.get('summary', 'Analysis complete')}",
        extra_data={
            "provider": llm_response.provider,
            "model": llm_response.model,
            "confidence": analysis_output.get("confidence_score"),
            "severity": analysis_output.get("severity"),
            "attack_type": analysis_output.get("attack_type"),
        },
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)

    await db.flush()
    logger.info(
        "Triage complete for incident %s: severity=%s, attack_type=%s, confidence=%.2f",
        incident.id,
        analysis_output.get("severity"),
        analysis_output.get("attack_type"),
        analysis_output.get("confidence_score", 0),
    )

    return ai_analysis


async def auto_triage_incident(
    db: AsyncSession,
    incident_id: uuid_mod.UUID,
) -> AiAnalysis | None:
    """Automatically triage an incident using the system-level LLM key.
    Called by Celery when a new incident is created from log correlation.
    Returns None if auto-triage is not configured."""
    from app.config import get_settings
    settings = get_settings()

    if not settings.auto_triage_enabled or not settings.auto_triage_api_key:
        logger.info("Auto-triage skipped for incident %s: not configured", incident_id)
        return None

    # Get the incident
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        logger.warning("Auto-triage: incident %s not found", incident_id)
        return None

    # Skip if already triaged
    if incident.status not in (IncidentStatus.NEW,):
        logger.info("Auto-triage skipped for incident %s: status is %s", incident_id, incident.status.value)
        return None

    # Get associated log events
    result = await db.execute(
        select(LogEvent)
        .where(LogEvent.incident_id == incident_id)
        .order_by(LogEvent.time_generated.asc())
    )
    log_events = list(result.scalars().all())

    if not log_events and incident.correlation_id:
        result = await db.execute(
            select(LogEvent)
            .where(LogEvent.correlation_id == incident.correlation_id)
            .order_by(LogEvent.time_generated.asc())
        )
        log_events = list(result.scalars().all())

    if not log_events:
        logger.warning("Auto-triage: no events for incident %s", incident_id)
        return None

    # Prepare event data
    events_data = []
    for event in log_events:
        events_data.append({
            "log_type": event.log_type,
            "time_generated": str(event.time_generated),
            "severity": event.severity,
            "summary": event.summary,
            "source_ip": str(event.source_ip) if event.source_ip else None,
            "destination_ip": str(event.destination_ip) if event.destination_ip else None,
            "user_identity": event.user_identity,
            "host": event.host,
            "correlation_id": event.correlation_id,
            "raw_data": event.raw_data,
        })

    incident_context = {
        "id": str(incident.id),
        "title": incident.title,
        "current_severity": incident.severity.value if incident.severity else "unknown",
        "attack_type": incident.attack_type,
        "status": incident.status.value if incident.status else "new",
    }

    # Get system-level provider
    try:
        provider = get_system_provider()
    except Exception as e:
        logger.error("Auto-triage failed to get provider: %s", e)
        return None

    # --- Step 1: Auto-enrichment ---
    enrichment_data = None
    if settings.auto_enrichment_enabled:
        from app.services.enrichment_service import extract_iocs, enrich_iocs
        try:
            iocs = extract_iocs(events_data)
            if any(iocs.values()):
                enrichment_data = await enrich_iocs(db, iocs, max_per_type=settings.auto_enrichment_max_iocs)
                if enrichment_data.get("enrichment_sources"):
                    logger.info("Auto-enrichment for incident %s: queried %s (%d IOCs)",
                                incident_id, enrichment_data["enrichment_sources"],
                                sum(len(iocs[k]) for k in iocs))
        except Exception as e:
            logger.warning("Auto-enrichment failed for incident %s: %s", incident_id, e)
            enrichment_data = None

    # --- Step 2: AI Triage ---
    logger.info("Auto-triaging incident %s (%s) with %d events",
                incident_id, incident.title, len(events_data))

    prompt = build_triage_prompt(events_data, incident_context, enrichment_data=enrichment_data)
    llm_response = await provider.analyze_with_json(
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        user_prompt=prompt,
        model=settings.auto_triage_model,
    )

    analysis_output = _safe_parse_json(llm_response.content)

    # Update incident
    if "severity" in analysis_output:
        try:
            incident.severity = IncidentSeverity(analysis_output["severity"])
        except ValueError:
            pass
    if "attack_type" in analysis_output and analysis_output["attack_type"]:
        incident.attack_type = analysis_output["attack_type"]
    if "confidence_score" in analysis_output:
        incident.confidence_score = analysis_output["confidence_score"]
    if "mitre_tactics" in analysis_output:
        incident.mitre_tactics = analysis_output["mitre_tactics"]
    if "mitre_techniques" in analysis_output:
        incident.mitre_techniques = analysis_output["mitre_techniques"]

    # Set status based on AI recommendation
    if analysis_output.get("requires_human_review", False):
        incident.status = IncidentStatus.AWAITING_ANALYST
    else:
        incident.status = IncidentStatus.TRIAGING

    # Store analysis
    ai_analysis = AiAnalysis(
        incident_id=incident.id,
        provider=llm_response.provider,
        model=llm_response.model,
        prompt_tokens=llm_response.prompt_tokens,
        completion_tokens=llm_response.completion_tokens,
        analysis_type="auto_triage",
        input_summary=f"Auto-triage of {len(log_events)} events for incident {incident.title}",
        output=analysis_output,
        confidence_score=analysis_output.get("confidence_score"),
        recommended_actions=analysis_output.get("recommended_actions"),
    )

    # Match playbook
    suggested = analysis_output.get("suggested_playbook")
    if suggested:
        result = await db.execute(
            select(Playbook).where(
                Playbook.is_active == True,
                Playbook.attack_types.contains([suggested]),
            )
        )
        playbook = result.scalar_one_or_none()
        if playbook:
            ai_analysis.recommended_playbook_id = playbook.id
            incident.playbook_id = playbook.id
            incident.current_playbook_step = 0

    db.add(ai_analysis)

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="auto_triage",
        actor="system",
        description=f"Automated AI triage: {analysis_output.get('summary', 'Analysis complete')}",
        extra_data={
            "provider": llm_response.provider,
            "model": llm_response.model,
            "confidence": analysis_output.get("confidence_score"),
            "severity": analysis_output.get("severity"),
            "attack_type": analysis_output.get("attack_type"),
            "automated": True,
            "enrichment_sources": enrichment_data.get("enrichment_sources", []) if enrichment_data else [],
        },
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)

    # --- Step 3: Auto-containment ---
    recommended_actions = analysis_output.get("recommended_actions", [])
    if recommended_actions:
        from app.services.action_service import create_action
        from app.models.action import ActionSource, ActionStatus, ActionLog

        confidence = analysis_output.get("confidence_score", 0)
        actions_created = 0
        actions_auto_executed = 0

        for rec in recommended_actions:
            action_type = rec.get("action")
            if not action_type:
                continue

            action_params = {}
            target = rec.get("target")
            if target:
                param_key = _action_param_key(action_type)
                action_params[param_key] = target

            # Dedup: skip if identical action already exists for this incident
            existing = await db.execute(
                select(ActionLog).where(
                    ActionLog.incident_id == incident.id,
                    ActionLog.action_type == action_type,
                    ActionLog.status.in_([
                        ActionStatus.PENDING_APPROVAL,
                        ActionStatus.APPROVED,
                        ActionStatus.EXECUTING,
                        ActionStatus.COMPLETED,
                    ]),
                )
            )
            if existing.scalar_one_or_none():
                continue

            can_auto = rec.get("can_auto_execute", False)
            auto_execute = can_auto and confidence >= settings.auto_response_confidence_threshold

            try:
                await create_action(
                    db=db,
                    incident_id=incident.id,
                    action_type=action_type,
                    action_params=action_params if action_params else None,
                    source=ActionSource.AI_RECOMMENDED,
                    requested_by="system",
                    auto_execute=auto_execute,
                    confidence=confidence,
                    auto_threshold=settings.auto_response_confidence_threshold,
                )
                actions_created += 1
                if auto_execute:
                    actions_auto_executed += 1
            except Exception as e:
                logger.error("Failed to create action %s for incident %s: %s",
                            action_type, incident.id, e)

        if actions_created > 0:
            logger.info(
                "Auto-containment for incident %s: %d actions created, %d auto-executed",
                incident.id, actions_created, actions_auto_executed,
            )

    await db.flush()
    logger.info(
        "Auto-triage complete for incident %s: severity=%s, attack=%s, confidence=%.2f, human_review=%s",
        incident.id,
        analysis_output.get("severity"),
        analysis_output.get("attack_type"),
        analysis_output.get("confidence_score", 0),
        analysis_output.get("requires_human_review", False),
    )

    return ai_analysis


async def correlate_with_ai(
    db: AsyncSession,
    correlation_id: str,
    user_id: uuid_mod.UUID,
    provider_name: str | None = None,
) -> AiAnalysis:
    """Run AI correlation analysis on events sharing a correlation ID."""

    result = await db.execute(
        select(LogEvent)
        .where(LogEvent.correlation_id == correlation_id)
        .order_by(LogEvent.time_generated.asc())
    )
    events = result.scalars().all()

    if not events:
        raise NotFoundError(f"No events found for correlation ID: {correlation_id}")

    events_data = []
    for event in events:
        events_data.append({
            "log_type": event.log_type,
            "time_generated": str(event.time_generated),
            "severity": event.severity,
            "summary": event.summary,
            "source_ip": str(event.source_ip) if event.source_ip else None,
            "user_identity": event.user_identity,
            "host": event.host,
            "raw_data": event.raw_data,
        })

    provider = await get_provider_for_user(db, user_id, provider_name)

    prompt = build_correlation_prompt(events_data)
    llm_response = await provider.analyze_with_json(
        system_prompt=CORRELATION_SYSTEM_PROMPT,
        user_prompt=prompt,
    )

    analysis_output = _safe_parse_json(llm_response.content)

    # Find or create incident for this correlation
    result = await db.execute(
        select(Incident).where(Incident.correlation_id == correlation_id)
    )
    incident = result.scalar_one_or_none()

    if not incident:
        from app.services.correlation import find_or_create_incident_for_correlation
        normalized = [{"severity": e.severity, "log_type": e.log_type, "summary": e.summary,
                       "source_ip": str(e.source_ip) if e.source_ip else None,
                       "host": e.host, "user_identity": e.user_identity,
                       "raw_data": e.raw_data, "tenant_id": e.tenant_id}
                      for e in events]
        incident = await find_or_create_incident_for_correlation(db, correlation_id, normalized)

    ai_analysis = AiAnalysis(
        incident_id=incident.id if incident else None,
        provider=llm_response.provider,
        model=llm_response.model,
        prompt_tokens=llm_response.prompt_tokens,
        completion_tokens=llm_response.completion_tokens,
        analysis_type="correlation",
        input_summary=f"Correlation analysis of {len(events)} events (correlation_id: {correlation_id})",
        output=analysis_output,
        confidence_score=analysis_output.get("confidence"),
    )
    db.add(ai_analysis)
    await db.flush()

    return ai_analysis
