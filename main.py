"""
main.py
--------
Pipeline orchestrator - runs the full OSINT threat-intelligence pipeline
end to end, in order, on a fresh database.

    COLLECTION  ->  PROCESSING  ->  SCORING

Run from the project root with:  python main.py
"""

from core.database import DB_PATH, init_db
from collection.runner import run_collection
from processing.runner import run_processing
from scoring.runner import run_scoring


def run_pipeline():
    """Run every stage of the pipeline in order on a clean database."""
    # Start from a clean database so every run is reproducible.
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()

    print("=" * 60)
    print("OSINT THREAT-INTELLIGENCE PIPELINE")
    print("=" * 60)

    print("\n[STAGE 1/3] COLLECTION")
    run_collection()

    print("\n[STAGE 2/3] PROCESSING & ENRICHMENT")
    run_processing()

    print("\n[STAGE 3/3] SCORING & CORRELATION")
    run_scoring()

    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    run_pipeline()