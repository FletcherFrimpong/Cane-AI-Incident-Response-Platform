import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user
from app.models.user import User
from app.models.triage import AiAnalysis
from app.schemas.triage import TriageRequest, TriageResponse, CorrelationRequest
from app.services.triage_service import triage_incident, correlate_with_ai
from app.exceptions import NotFoundError

router = APIRouter()


@router.post("/analyze", response_model=TriageResponse)
async def analyze_incident(
    request: TriageRequest,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    """Trigger AI triage analysis on an incident."""
    try:
        analysis = await triage_incident(
            db=db,
            incident_id=request.incident_id,
            user_id=current_user.id,
            provider_name=request.provider,
            model=request.model,
            actor=current_user.email,
        )
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 - surface provider failures (bad key, no credit) readably
        body = getattr(e, "body", None)
        message = None
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            message = body["error"].get("message")
        raise HTTPException(status_code=502, detail=f"LLM provider error: {message or e}")
    return analysis


@router.get("/{incident_id}", response_model=list[TriageResponse])
async def get_triage_results(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    """Get all AI analysis results for an incident."""
    result = await db.execute(
        select(AiAnalysis)
        .where(AiAnalysis.incident_id == incident_id)
        .order_by(AiAnalysis.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{incident_id}/recommendations")
async def get_recommendations(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    """Get AI-recommended actions for an incident."""
    result = await db.execute(
        select(AiAnalysis)
        .where(AiAnalysis.incident_id == incident_id, AiAnalysis.analysis_type.in_(["triage", "auto_triage"]))
        .order_by(AiAnalysis.created_at.desc())
        .limit(1)
    )
    analysis = result.scalars().first()
    if not analysis:
        raise NotFoundError("No triage analysis found. Run /triage/analyze first.")

    return {
        "incident_id": str(incident_id),
        "recommended_actions": analysis.recommended_actions or [],
        "requires_human_review": analysis.output.get("requires_human_review", False),
        "human_review_reason": analysis.output.get("human_review_reason"),
        "suggested_playbook": analysis.output.get("suggested_playbook"),
        "confidence_score": analysis.confidence_score,
    }


@router.post("/correlate")
async def correlate_events(
    request: CorrelationRequest,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    """Run AI correlation analysis on events sharing a correlation ID."""
    analysis = await correlate_with_ai(
        db=db,
        correlation_id=request.correlation_id,
        user_id=current_user.id,
        provider_name=request.provider,
    )
    return TriageResponse.model_validate(analysis)
