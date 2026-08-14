"""Store a tenant credential with a one-hour lifetime."""

import asyncio
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import vaultlet


async def main() -> None:
    """Run the credential example."""
    with TemporaryDirectory(prefix="vaultlet-credentials-") as directory:
        key = vaultlet.MasterKey.generate()
        async with await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(Path(directory) / "credentials.vaultlet"), key=key
        ) as store:
            credentials = store.tenant("customer-123")
            await credentials.set("access-token", b"secret", ttl=timedelta(hours=1))
            if await credentials.get("access-token") != b"secret":
                raise RuntimeError("credential did not round-trip")


asyncio.run(main())
