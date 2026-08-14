"""Fast benchmark-scenario correctness smoke used by CI."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from compare import vaultlet_bytes, vaultlet_json

import vaultlet


def main() -> None:
    """Exercise both end-to-end benchmark workloads once."""
    with tempfile.TemporaryDirectory(prefix="vaultlet-bench-smoke-") as directory:
        path = Path(directory)
        for engine in vaultlet.StorageEngine:
            asyncio.run(vaultlet_bytes(path, engine=engine, size=64, tasks=1))
        asyncio.run(vaultlet_json(path, engine=vaultlet.StorageEngine.SQLITE, tasks=1))


if __name__ == "__main__":
    main()
