"""Open one shared store, overlap with peers, and commit one atomic batch."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import vaultlet


def wait_for_release(ready: Path, release: Path) -> None:
    """Signal readiness and block this helper thread until the parent releases it."""
    ready.touch()
    while not release.exists():
        time.sleep(0.01)


async def main() -> None:
    """Wait until every process is open, then write a distinct batch."""
    path, encoded_key, ready_value, release_value, prefix, count_value = sys.argv[1:]
    store = await vaultlet.Vaultlet.open(
        vaultlet.FileBackend(path),
        key=vaultlet.MasterKey.from_base64(encoded_key),
        cleanup_interval=0,
    )
    ready = Path(ready_value)
    release = Path(release_value)
    await asyncio.to_thread(wait_for_release, ready, release)
    count = int(count_value)
    await store.tenant("tenant").set_many(
        {
            f"{prefix}-{index}": f"value-{prefix}-{index}".encode()
            for index in range(count)
        }
    )
    await store.aclose()


asyncio.run(main())
