from pydantic import BaseModel


class DashboardOverview(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    awaiting_analyst: int
    mean_time_to_respond_minutes: float | None
    incidents_today: int
    incidents_this_week: int


class ThreatDistribution(BaseModel):
    attack_type: str
    count: int


class GeoThreatData(BaseModel):
    latitude: float
    longitude: float
    country: str
    city: str | None
    incident_count: int
    severity: str


class AnalystWorkload(BaseModel):
    analyst_id: str
    analyst_name: str
    open_incidents: int
    avg_response_time_minutes: float | None
