from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.incidents import router as incidents_router
from app.api.logs import router as logs_router
from app.api.playbooks import router as playbooks_router
from app.api.triage import router as triage_router
from app.api.actions import router as actions_router
from app.api.dashboard import router as dashboard_router
from app.api.integrations import router as integrations_router

api_router = APIRouter()

api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users_router, prefix="/users", tags=["Users"])
api_router.include_router(incidents_router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(logs_router, prefix="/logs", tags=["Logs"])
api_router.include_router(playbooks_router, prefix="/playbooks", tags=["Playbooks"])
api_router.include_router(triage_router, prefix="/triage", tags=["AI Triage"])
api_router.include_router(actions_router, prefix="/actions", tags=["Actions"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(integrations_router, prefix="/integrations", tags=["Integrations"])
