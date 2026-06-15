#!/usr/bin/env python3
"""Load demo organizational memory data for hackathon demos (Aurora DSQL / Postgres)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Repo root = parent of scripts/
REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = REPO_ROOT / "demo_data"

# Ensure `specter` package resolves when run as `uv run python ../../scripts/init_demo_data.py`
_BACKEND_SRC = REPO_ROOT / "packages" / "backend" / "src"
if _BACKEND_SRC.is_dir():
    sys.path.insert(0, str(_BACKEND_SRC))


async def init_demo_data(*, demo_dir: Path) -> None:
    from specter.memory.db import init_db
    from specter.memory.ingestion import MemoryIngestionPipeline

    await init_db()
    pipeline = MemoryIngestionPipeline()

    def load(name: str) -> list | dict:
        path = demo_dir / name
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)

    print("Ingesting assets...")
    assets = load("assets.json")
    assert isinstance(assets, list)
    ids = await pipeline.ingest_asset_inventory(assets)
    print(f"  -> {len(ids)} asset entities")

    print("Ingesting users...")
    users = load("users.json")
    assert isinstance(users, list)
    uids = await pipeline.ingest_user_directory(users)
    print(f"  -> {len(uids)} user entities")

    print("Ingesting network topology...")
    connections = load("network.json")
    assert isinstance(connections, list)
    n = await pipeline.ingest_network_topology(connections)
    print(f"  -> {n} edges")

    print("Ingesting threat intel...")
    threats = load("threats.json")
    assert isinstance(threats, list)
    tids = await pipeline.ingest_threat_intel(threats)
    print(f"  -> {len(tids)} threat entities")

    print("\nDemo data loaded. Organizational memory is primed for demos.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--demo-dir",
        type=Path,
        default=DEMO_DIR,
        help=f"Directory with JSON fixtures (default: {DEMO_DIR})",
    )
    args = parser.parse_args()
    asyncio.run(init_demo_data(demo_dir=args.demo_dir))


if __name__ == "__main__":
    main()
