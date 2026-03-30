"""Ingest all synthetic log files from the synthetic_logs directory."""
import asyncio
import json
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import async_session_factory
from app.services.log_ingestion import ingest_batch


SYNTHETIC_LOGS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "synthetic_logs"


async def ingest_file(filepath: Path):
    """Ingest a single JSON log file."""
    with open(filepath) as f:
        raw = json.load(f)

    # Normalize to list
    events = raw if isinstance(raw, list) else [raw]

    if not events:
        print(f"  SKIP {filepath.name}: empty")
        return 0, 0, 0

    async with async_session_factory() as session:
        result = await ingest_batch(session, events)
        await session.commit()

    ingested = result.get("ingested", 0)
    errors = result.get("errors", 0)
    incidents = result.get("incidents_created", 0)
    print(f"  {filepath.name}: {ingested} ingested, {errors} errors, {incidents} incidents created")
    if result.get("error_details"):
        for err in result["error_details"][:3]:
            print(f"    ERROR: {err}")
    return ingested, errors, incidents


async def main():
    if not SYNTHETIC_LOGS_DIR.exists():
        print(f"ERROR: synthetic_logs directory not found at {SYNTHETIC_LOGS_DIR}")
        sys.exit(1)

    json_files = sorted(SYNTHETIC_LOGS_DIR.glob("*.json"))
    if not json_files:
        print("No JSON files found in synthetic_logs/")
        sys.exit(1)

    print(f"Found {len(json_files)} log files in {SYNTHETIC_LOGS_DIR}\n")

    total_ingested = 0
    total_errors = 0
    total_incidents = 0

    for filepath in json_files:
        try:
            ingested, errors, incidents = await ingest_file(filepath)
            total_ingested += ingested
            total_errors += errors
            total_incidents += incidents
        except Exception as e:
            print(f"  FAILED {filepath.name}: {e}")
            total_errors += 1

    print(f"\n{'='*50}")
    print(f"Total: {total_ingested} events ingested, {total_errors} errors, {total_incidents} incidents created")


if __name__ == "__main__":
    asyncio.run(main())
