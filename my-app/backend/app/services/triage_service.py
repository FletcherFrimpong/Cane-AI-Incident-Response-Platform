"""
Triage service: orchestrates AI analysis of security incidents.

One pipeline serves both entry points:
  - `auto_triage_incident`  (Celery, system key)  - may auto-execute allow-listed actions
  - `triage_incident`       (analyst clicks "Run AI triage") - only ever queues actions

Pipeline: load evidence -> enrich IOCs -> ask the LLM -> validate its reply ->
update the incident -> commit -> create actions one by one (see triage_guard for
the rules on what may run unattended).
"""

import logging
import uuid as uuid_mod
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.prompts.triage import (
    CORRELATION_SYSTEM_PROMPT,
    TRIAGE_SYSTEM_PROMPT,
    build_correlation_prompt,
    build_triage_prompt,
)
from app.ai.provider_base import LLMRefusalError
from app.ai.provider_factory import get_provider_for_user, get_system_provider
from app.config import get_settings
from app.exceptions import NotFoundError
from app.models.action import ActionSource
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentTimeline
from app.models.log_event import LogEvent
from app.models.triage import AiAnalysis
from app.services.action_service import create_action, find_active_duplicate
from app.services.playbook_service import first_step_order, match_playbook
from app.services.triage_guard import (
    TriageParseError,
    extract_json_object,
    observed_entities,
    parse_triage_output,
    plan_action,
)

logger = logging.getLogger("cane_ai.triage")

# Statuses an analyst (or a playbook) has put the incident in; AI triage must not
# drag an incident someone is already working back to an earlier stage.
_AI_MAY_SET_STATUS_FROM = (IncidentStatus.NEW, IncidentStatus.TRIAGING, IncidentStatus.AWAITING_ANALYST)


def _event_to_prompt_dict(event: LogEvent) -> dict:
    return {
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
    }


async def _load_incident_events(db: AsyncSession, incident: Incident) -> list[LogEvent]:
    result = await db.execute(
        select(LogEvent).where(LogEvent.incident_id == incident.id).order_by(LogEvent.time_generated.asc())
    )
    events = list(result.scalars().all())
    if not events and incident.correlation_id:
        result = await db.execute(
            select(LogEvent)
            .where(LogEvent.correlation_id == incident.correlation_id)
            .order_by(LogEvent.time_generated.asc())
        )
        events = list(result.scalars().all())
    return events


async def _enrich(db: AsyncSession, incident: Incident, events_data: list[dict]) -> dict | None:
    settings = get_settings()
    if not settings.auto_enrichment_enabled:
        return incident.enrichment
    from app.services.enrichment_service import enrich_incident_data
    try:
        data = await enrich_incident_data(db, events_data, max_per_type=settings.auto_enrichment_max_iocs)
    except Exception as e:  # noqa: BLE001 - enrichment is best-effort
        logger.warning("Enrichment failed for incident %s: %s", incident.id, e)
        return incident.enrichment
    if data is not None:
        incident.enrichment = data
    return data


async def enrich_incident(db: AsyncSession, incident_id: uuid_mod.UUID) -> dict | None:
    """Run enrichment for an incident on its own (no AI involved) and store it."""
    incident = (await db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")
    events = await _load_incident_events(db, incident)
    data = await _enrich(db, incident, [_event_to_prompt_dict(e) for e in events])
    await db.flush()
    return data


async def _record_failed_triage(
    db: AsyncSession, incident: Incident, analysis_type: str, provider: str, model: str,
    reason: str, raw: str | None, actor: str,
) -> AiAnalysis:
    """The AI could not produce a usable assessment. Say so plainly and hand the
    incident to a person, rather than storing junk as if it were an analysis."""
    analysis = AiAnalysis(
        incident_id=incident.id,
        provider=provider,
        model=model,
        analysis_type=f"{analysis_type}_failed",
        input_summary=f"Triage of incident {incident.title}",
        output={"error": reason, "raw": (raw or "")[:2000], "requires_human_review": True},
    )
    db.add(analysis)
    if incident.status in _AI_MAY_SET_STATUS_FROM:
        incident.status = IncidentStatus.AWAITING_ANALYST
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="ai_analysis_failed",
        actor=actor,
        description=f"AI triage could not complete ({reason}). Manual review required.",
        extra_data={"provider": provider, "model": model},
        timestamp=datetime.now(timezone.utc),
    ))
    await db.commit()
    return analysis


async def _run_triage(
    db: AsyncSession,
    incident: Incident,
    provider,
    model: str | None,
    analysis_type: str,
    actor: str,
    allow_auto_execute: bool,
) -> AiAnalysis:
    settings = get_settings()
    log_events = await _load_incident_events(db, incident)
    if not log_events:
        raise NotFoundError("No log events found for this incident")
    events_data = [_event_to_prompt_dict(e) for e in log_events]

    incident_context = {
        "id": str(incident.id),
        "title": incident.title,
        "current_severity": incident.severity.value if incident.severity else "unknown",
        "attack_type": incident.attack_type,
        "status": incident.status.value if incident.status else "new",
        "total_events": len(events_data),
    }

    enrichment_data = await _enrich(db, incident, events_data)

    logger.info("Triaging incident %s (%s) with %d events", incident.id, incident.title, len(events_data))
    prompt = build_triage_prompt(events_data, incident_context, enrichment_data=enrichment_data)
    provider_label = getattr(provider, "provider_name", "unknown")
    try:
        llm_response = await provider.analyze_with_json(
            system_prompt=TRIAGE_SYSTEM_PROMPT,
            user_prompt=prompt,
            model=model,
        )
    except LLMRefusalError as e:
        return await _record_failed_triage(db, incident, analysis_type, provider_label, model or "default",
                                           str(e), None, actor)

    try:
        output = parse_triage_output(llm_response.content)
    except TriageParseError as e:
        logger.warning("Unusable triage reply for incident %s: %s", incident.id, e)
        return await _record_failed_triage(db, incident, analysis_type, llm_response.provider,
                                           llm_response.model, str(e), llm_response.content, actor)

    # ---- Decide what happens to each recommended action (pure rules, no I/O)
    observed = observed_entities(events_data)
    plans = [
        plan_action(
            rec, observed, output.confidence_score, output.requires_human_review,
            settings.auto_execute_action_types, settings.auto_response_confidence_threshold,
            allow_auto=allow_auto_execute,
        )
        for rec in output.recommended_actions
    ]
    actionable = [p for p in plans if p.disposition != "skip"]

    # ---- Update the incident
    incident.severity = IncidentSeverity(output.severity)
    if output.attack_type:
        incident.attack_type = output.attack_type[:100]
    incident.confidence_score = output.confidence_score
    incident.mitre_tactics = output.mitre_tactics
    incident.mitre_techniques = output.mitre_techniques

    needs_analyst = output.requires_human_review or any(p.disposition == "queue" for p in actionable)
    if incident.status in _AI_MAY_SET_STATUS_FROM:
        incident.status = IncidentStatus.AWAITING_ANALYST if needs_analyst else IncidentStatus.TRIAGING

    analysis_output = output.model_dump()
    analysis_output["action_decisions"] = [p.as_dict() for p in plans]
    ai_analysis = AiAnalysis(
        incident_id=incident.id,
        provider=llm_response.provider,
        model=llm_response.model,
        prompt_tokens=llm_response.prompt_tokens,
        completion_tokens=llm_response.completion_tokens,
        analysis_type=analysis_type,
        input_summary=f"Triage of {len(log_events)} events for incident {incident.title}",
        output=analysis_output,
        confidence_score=output.confidence_score,
        recommended_actions=[a.model_dump() for a in output.recommended_actions],
    )

    playbook = await match_playbook(db, output.suggested_playbook or output.attack_type)
    if playbook:
        ai_analysis.recommended_playbook_id = playbook.id
        if incident.playbook_id is None:
            incident.playbook_id = playbook.id
            incident.current_playbook_step = await first_step_order(db, playbook.id)

    db.add(ai_analysis)
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="auto_triage" if analysis_type == "auto_triage" else "ai_analysis",
        actor=actor,
        description=f"AI triage completed: {output.summary}",
        extra_data={
            "provider": llm_response.provider,
            "model": llm_response.model,
            "confidence": output.confidence_score,
            "severity": output.severity,
            "attack_type": output.attack_type,
            "automated": analysis_type == "auto_triage",
            "enrichment_sources": enrichment_data.get("sources", []) if enrichment_data else [],
            "playbook": playbook.name if playbook else None,
        },
        timestamp=datetime.now(timezone.utc),
    ))
    # Commit the assessment before touching any external system: whatever happens
    # during containment, the analysis and the incident's new state are kept.
    await db.commit()

    # ---- Containment: one action at a time, each committed on its own
    created = executed = 0
    for plan in actionable:
        try:
            if await find_active_duplicate(db, incident.id, plan.action_type, plan.params):
                continue
            await create_action(
                db=db,
                incident_id=incident.id,
                action_type=plan.action_type,
                action_params=plan.params,
                source=ActionSource.AI_RECOMMENDED,
                requested_by="system" if analysis_type == "auto_triage" else actor,
                auto_execute=plan.disposition == "auto",
                reason=plan.reason,
            )
            await db.commit()
            created += 1
            executed += plan.disposition == "auto"
        except Exception as e:  # noqa: BLE001 - one bad action must not stop the rest
            await db.rollback()
            logger.error("Failed to create action %s for incident %s: %s", plan.action_type, incident.id, e)

    if playbook and incident.playbook_id == playbook.id:
        try:
            from app.services.playbook_service import run_current_step
            await run_current_step(db, incident.id)
            await db.commit()
        except Exception as e:  # noqa: BLE001
            await db.rollback()
            logger.error("Could not start playbook step for incident %s: %s", incident.id, e)

    logger.info(
        "Triage complete for incident %s: severity=%s attack=%s confidence=%.2f human_review=%s "
        "actions: %d created, %d auto-executed, %d dropped by guard",
        incident.id, output.severity, output.attack_type, output.confidence_score,
        output.requires_human_review, created, executed, len(plans) - len(actionable),
    )
    return ai_analysis


async def record_triage_error(db: AsyncSession, incident_id: uuid_mod.UUID, reason: str) -> None:
    """Automated triage gave up (provider down, key rejected, out of credit).
    Put the incident in front of an analyst with the reason on its timeline."""
    incident = (await db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
    if not incident or incident.status != IncidentStatus.NEW:
        return
    settings = get_settings()
    await _record_failed_triage(
        db, incident, "auto_triage", settings.auto_triage_provider,
        settings.auto_triage_model or "default", reason[:300], None, "system",
    )


async def triage_incident(
    db: AsyncSession,
    incident_id: uuid_mod.UUID,
    user_id: uuid_mod.UUID,
    provider_name: str | None = None,
    model: str | None = None,
    actor: str = "analyst",
) -> AiAnalysis:
    """Analyst-triggered AI triage. Uses the analyst's own LLM key, or the system key
    if they have none. Recommended actions are queued for approval, never executed."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    provider = await get_provider_for_user(db, user_id, provider_name)
    return await _run_triage(db, incident, provider, model, "triage", actor, allow_auto_execute=False)


async def auto_triage_incident(
    db: AsyncSession,
    incident_id: uuid_mod.UUID,
) -> AiAnalysis | None:
    """Automatically triage a new incident with the system-level LLM key (Celery).
    Returns None when auto-triage is not configured or does not apply."""
    from app.ai.provider_factory import system_provider_configured
    settings = get_settings()
    if not settings.auto_triage_enabled or not system_provider_configured():
        # No AI configured: still gather threat intel and context for the analyst.
        try:
            await enrich_incident(db, incident_id)
            await db.commit()
        except Exception as e:  # noqa: BLE001
            await db.rollback()
            logger.warning("Enrichment for incident %s failed: %s", incident_id, e)
        return None

    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        # Dispatch happens after commit, so this means the incident was deleted.
        logger.warning("Auto-triage: incident %s not found", incident_id)
        return None

    if incident.status != IncidentStatus.NEW:
        logger.info("Auto-triage skipped for incident %s: status is %s", incident_id, incident.status.value)
        return None

    try:
        return await _run_triage(
            db, incident, get_system_provider(), settings.auto_triage_model,
            "auto_triage", "system", allow_auto_execute=True,
        )
    except NotFoundError as e:
        logger.warning("Auto-triage skipped for incident %s: %s", incident_id, e.detail)
        return None


async def correlate_with_ai(
    db: AsyncSession,
    correlation_id: str,
    user_id: uuid_mod.UUID,
    provider_name: str | None = None,
) -> AiAnalysis:
    """Run AI correlation analysis (attack narrative) on events sharing a correlation ID."""
    result = await db.execute(
        select(LogEvent)
        .where(LogEvent.correlation_id == correlation_id)
        .order_by(LogEvent.time_generated.asc())
    )
    events = result.scalars().all()
    if not events:
        raise NotFoundError(f"No events found for correlation ID: {correlation_id}")

    incident = (await db.execute(
        select(Incident).where(Incident.correlation_id == correlation_id).order_by(Incident.created_at.asc()).limit(1)
    )).scalars().first()
    if not incident:
        raise NotFoundError("These events have not been raised to an incident, so there is nothing to attach an analysis to")

    provider = await get_provider_for_user(db, user_id, provider_name)
    llm_response = await provider.analyze_with_json(
        system_prompt=CORRELATION_SYSTEM_PROMPT,
        user_prompt=build_correlation_prompt([_event_to_prompt_dict(e) for e in events]),
    )
    try:
        analysis_output = extract_json_object(llm_response.content)
    except TriageParseError as e:
        analysis_output = {"error": str(e), "raw": llm_response.content[:2000]}

    confidence = analysis_output.get("confidence")
    ai_analysis = AiAnalysis(
        incident_id=incident.id,
        provider=llm_response.provider,
        model=llm_response.model,
        prompt_tokens=llm_response.prompt_tokens,
        completion_tokens=llm_response.completion_tokens,
        analysis_type="correlation",
        input_summary=f"Correlation analysis of {len(events)} events (correlation_id: {correlation_id})",
        output=analysis_output,
        confidence_score=confidence if isinstance(confidence, (int, float)) and 0 <= confidence <= 1 else None,
    )
    db.add(ai_analysis)
    await db.flush()
    return ai_analysis
