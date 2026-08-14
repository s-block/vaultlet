"""Keep identical logical keys isolated across tenants."""

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

import vaultlet


async def main() -> None:
    """Run the multi-tenant example."""
    with TemporaryDirectory(prefix="vaultlet-tenants-") as directory:
        key = vaultlet.MasterKey.generate()
        async with await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(Path(directory) / "tenants.vaultlet"), key=key
        ) as store:
            await store.tenant("first").set("token", b"first-secret")
            await store.tenant("second").set("token", b"second-secret")


asyncio.run(main())
