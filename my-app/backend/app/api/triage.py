import uuid
from fastapi import APIRouter, Depends
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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Trigger AI triage analysis on an incident."""
    analysis = await triage_incident(
        db=db,
        incident_id=request.incident_id,
        user_id=current_user.id,
        provider_name=request.provider,
        model=request.model,
    )
    return analysis


@router.get("/{incident_id}", response_model=list[TriageResponse])
async def get_triage_results(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get all AI analysis results for an incident."""
    result = await db.execute(
        select(AiAnalysis)
        .where(AiAnalysis.incident_id == incident_id)
        .order_by(AiAnalysis.created_at.desc())
    )
    analyses = result.scalars().all()
    if not analyses:
        raise NotFoundError("No triage results found for this incident")
    return analyses


@router.get("/{incident_id}/recommendations")
async def get_recommendations(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get AI-recommended actions for an incident."""
    result = await db.execute(
        select(AiAnalysis)
        .where(AiAnalysis.incident_id == incident_id, AiAnalysis.analysis_type == "triage")
        .order_by(AiAnalysis.created_at.desc())
        .limit(1)
    )
    analysis = result.scalar_one_or_none()
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
    db: AsyncSession = Depends(get_db),
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
