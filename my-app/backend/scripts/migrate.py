"""Bring the database schema up to date. Run before starting the API:

    python scripts/migrate.py

- Empty database            -> every migration is applied.
- Database from before migrations existed (tables present, no alembic_version)
                            -> marked as being at the baseline, then upgraded.
- Otherwise                 -> upgraded to the latest revision.
"""

import asyncio
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

BASELINE = "0001"


async def _state() -> tuple[bool, bool]:
    import asyncpg

    from app.config import get_settings

    dsn = get_settings().database_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn)
    try:
        versioned = await conn.fetchval("select to_regclass('public.alembic_version') is not null")
        has_tables = await conn.fetchval("select to_regclass('public.incidents') is not null")
        return bool(versioned), bool(has_tables)
    finally:
        await conn.close()


def _alembic(*args: str) -> None:
    subprocess.run([sys.executable, "-m", "alembic", *args], cwd=BACKEND, check=True)


def main() -> None:
    versioned, has_tables = asyncio.run(_state())
    if not versioned and has_tables:
        print(f"Existing unversioned database: marking it as revision {BASELINE}")
        _alembic("stamp", BASELINE)
    _alembic("upgrade", "head")
    print("Database schema is up to date")


if __name__ == "__main__":
    main()
