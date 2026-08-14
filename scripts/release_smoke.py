"""Exercise an installed native wheel without importing the source tree."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import vaultlet


def require(condition: bool, message: str) -> None:
    """Fail the smoke run with an actionable message."""
    if not condition:
        raise RuntimeError(message)


async def main() -> None:
    """Verify shared opens, enumeration, and rotation in an installed wheel."""
    key = vaultlet.MasterKey.generate()
    replacement = vaultlet.MasterKey.generate()
    path = Path(tempfile.mkdtemp()) / "smoke.vaultlet"
    store = await vaultlet.Vaultlet.open(
        vaultlet.FileBackend(path), key=key, cleanup_interval=0
    )
    shared = await vaultlet.Vaultlet.open(
        vaultlet.FileBackend(path), key=key, cleanup_interval=0
    )
    await store.tenant("release").set("key", b"encrypted")
    require(
        await shared.tenant("release").get("key") == b"encrypted",
        "shared SQLite read failed",
    )
    require(
        await shared.tenant("release").keys()
        == vaultlet.KeyListing(keys=("key",), has_more=False),
        "encrypted key enumeration failed",
    )
    await store.rotate_master_key(replacement)
    await shared.aclose()
    await store.aclose()

    reopened = await vaultlet.Vaultlet.open(
        vaultlet.FileBackend(path), key=replacement, cleanup_interval=0
    )
    require(
        await reopened.tenant("release").get("key") == b"encrypted",
        "master-key rotation round trip failed",
    )
    await reopened.aclose()


asyncio.run(main())
