from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user
from app.models.user import User
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentTimeline
from app.models.log_event import LogEvent
from app.schemas.dashboard import DashboardOverview, ThreatDistribution, AnalystWorkload

router = APIRouter()


@router.get("/overview", response_model=DashboardOverview)
async def dashboard_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)

    # Total incidents
    total = (await db.execute(select(func.count(Incident.id)))).scalar() or 0

    # Open (not closed, not false_positive)
    open_count = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE])
        )
    )).scalar() or 0

    # By severity
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low"]:
        count = (await db.execute(
            select(func.count(Incident.id)).where(
                Incident.severity == sev,
                Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]),
            )
        )).scalar() or 0
        severity_counts[sev] = count

    # Awaiting analyst
    awaiting = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status == IncidentStatus.AWAITING_ANALYST)
    )).scalar() or 0

    # Incidents today and this week
    today_count = (await db.execute(
        select(func.count(Incident.id)).where(Incident.created_at >= today_start)
    )).scalar() or 0

    week_count = (await db.execute(
        select(func.count(Incident.id)).where(Incident.created_at >= week_start)
    )).scalar() or 0

    # MTTR (mean time to respond) for resolved incidents
    resolved = (await db.execute(
        select(Incident).where(Incident.resolved_at.isnot(None)).limit(100)
    )).scalars().all()

    mttr = None
    if resolved:
        durations = [(i.resolved_at - i.created_at).total_seconds() / 60 for i in resolved]
        mttr = sum(durations) / len(durations)

    return DashboardOverview(
        total_incidents=total,
        open_incidents=open_count,
        critical_incidents=severity_counts.get("critical", 0),
        high_incidents=severity_counts.get("high", 0),
        medium_incidents=severity_counts.get("medium", 0),
        low_incidents=severity_counts.get("low", 0),
        awaiting_analyst=awaiting,
        mean_time_to_respond_minutes=mttr,
        incidents_today=today_count,
        incidents_this_week=week_count,
    )


@router.get("/threats", response_model=list[ThreatDistribution])
async def threat_distribution(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(
        select(Incident.attack_type, func.count(Incident.id))
        .where(Incident.attack_type.isnot(None))
        .group_by(Incident.attack_type)
        .order_by(func.count(Incident.id).desc())
    )
    return [
        ThreatDistribution(attack_type=row[0], count=row[1])
        for row in result.all()
    ]


@router.get("/geo")
async def geo_threats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get geographic threat data from log events with location info."""
    result = await db.execute(
        select(LogEvent)
        .where(LogEvent.source_ip.isnot(None))
        .order_by(LogEvent.time_generated.desc())
        .limit(500)
    )
    events = result.scalars().all()

    geo_data = []
    for event in events:
        raw = event.raw_data or {}
        lat = raw.get("RemoteIPLatitude") or raw.get("GeoLocation", {}).get("Latitude") if isinstance(raw.get("GeoLocation"), dict) else None
        lon = raw.get("RemoteIPLongitude") or raw.get("GeoLocation", {}).get("Longitude") if isinstance(raw.get("GeoLocation"), dict) else None
        country = raw.get("RemoteIPCountry") or raw.get("GeoLocation", {}).get("Country", "") if isinstance(raw.get("GeoLocation"), dict) else ""

        if lat and lon:
            geo_data.append({
                "latitude": float(lat),
                "longitude": float(lon),
                "country": country,
                "city": raw.get("GeoLocation", {}).get("City") if isinstance(raw.get("GeoLocation"), dict) else None,
                "severity": event.severity,
                "log_type": event.log_type,
                "summary": event.summary,
            })

    return geo_data


@router.get("/timeline")
async def activity_timeline(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Recent activity feed."""
    result = await db.execute(
        select(IncidentTimeline)
        .order_by(IncidentTimeline.timestamp.desc())
        .limit(limit)
    )
    entries = result.scalars().all()
    return [
        {
            "id": str(e.id),
            "incident_id": str(e.incident_id),
            "event_type": e.event_type,
            "actor": e.actor,
            "description": e.description,
            "timestamp": str(e.timestamp),
        }
        for e in entries
    ]
