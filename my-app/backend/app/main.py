import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.middleware import RequestLoggingMiddleware
from app.api.router import api_router

settings = get_settings()

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.getLogger("cane_ai").info("Cane AI starting up...")
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
