import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.middleware import RequestLoggingMiddleware
from app.api.router import api_router
import app.services.events  # noqa: F401 - registers the change-feed listeners

settings = get_settings()

# passlib probes bcrypt's version in a way newer bcrypt releases no longer support and
# logs a harmless traceback every start; hashing itself works.
logging.getLogger("passlib").setLevel(logging.ERROR)

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def check_secrets() -> None:
    """Refuse to run with the JWT / encryption secrets published in this repository,
    unless explicitly in debug (local development) mode."""
    insecure = settings.insecure_defaults()
    if not insecure:
        return
    message = (f"{', '.join(insecure)} still set to the default value from the repository. "
               "Anyone could forge login tokens and decrypt stored credentials. "
               "Generate real values with: openssl rand -hex 32")
    if settings.debug:
        logging.getLogger("cane_ai").warning("INSECURE (allowed because CANE_DEBUG=true): %s", message)
    else:
        raise RuntimeError(message)


async def init_database() -> None:
    """Load the built-in playbooks. The schema itself is managed by Alembic:
    run `python scripts/migrate.py` before starting (docker-compose does)."""
    from sqlalchemy.exc import ProgrammingError

    from app.database import async_session_factory
    from app.services.playbook_service import seed_builtin_playbooks

    try:
        async with async_session_factory() as session:
            added = await seed_builtin_playbooks(session)
            await session.commit()
    except ProgrammingError as e:
        raise RuntimeError("Database tables are missing. Run: python scripts/migrate.py") from e
    if added:
        logging.getLogger("cane_ai").info("Loaded %d built-in playbooks", added)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log = logging.getLogger("cane_ai")
    log.info("Cane AI starting up...")
    check_secrets()
    await init_database()
    if not (settings.auto_triage_enabled and settings.auto_triage_api_key):
        log.info("Automated AI triage is OFF (set CANE_AUTO_TRIAGE_API_KEY to enable it)")
    yield
    logging.getLogger("cane_ai").info("Cane AI shutting down...")


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AI-powered incident response platform with human-in-the-loop triage",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestLoggingMiddleware)

app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": settings.app_name}
