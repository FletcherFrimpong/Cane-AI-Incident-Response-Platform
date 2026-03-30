from celery import Celery
from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "cane_ai",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "health-check-integrations": {
            "task": "app.workers.health_checks.check_integration_health",
            "schedule": 300.0,  # every 5 minutes
        },
    },
)

celery_app.autodiscover_tasks(["app.workers"])
