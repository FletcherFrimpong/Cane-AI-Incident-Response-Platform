from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    echo=False,  # SQL echo prints every parameter (tokens, hashes) to the logs
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncSession:
    """Request-scoped session; commits when the endpoint returns.

    Always depend on it as `Depends(get_db, scope="function")`. With the default
    scope FastAPI runs the commit only after the response has been sent, so a client
    that immediately follows a write with a read (the UI does, on every mutation)
    can be served the old data - or, for a deactivated account, still be let in."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def task_session_factory():
    """Session factory for code that runs outside the API's event loop (Celery tasks).

    Each Celery task runs in its own `asyncio.run()` loop, and asyncpg connections
    cannot be reused across loops. NullPool gives every task fresh connections that
    are closed when it finishes. Returns (engine, factory); dispose the engine after use.
    """
    from sqlalchemy.pool import NullPool

    task_engine = create_async_engine(settings.database_url, poolclass=NullPool)
    return task_engine, async_sessionmaker(task_engine, class_=AsyncSession, expire_on_commit=False)
