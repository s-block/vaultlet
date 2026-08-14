"""Subprocess helper that exits immediately after a durable write."""

from __future__ import annotations

import asyncio
import os
import sys

import vaultlet


async def main() -> None:
    """Commit a value, then bypass Python cleanup to simulate a process crash."""
    path, encoded_key, mode = sys.argv[1:]
    store = await vaultlet.Vaultlet.open(
        vaultlet.FileBackend(path),
        key=vaultlet.MasterKey.from_base64(encoded_key),
        cleanup_interval=0,
    )
    tenant = store.tenant("tenant")
    if mode == "committed":
        await tenant.set("committed", b"survives")
    elif mode == "interrupted":
        pending = asyncio.create_task(
            tenant.set_many(
                {f"batch-{index}": bytes(1024 * 1024) for index in range(16)}
            )
        )
        await asyncio.sleep(0)
        del pending
    else:
        raise ValueError("unknown crash helper mode")
    os._exit(0)


asyncio.run(main())
