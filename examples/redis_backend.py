"""Store encrypted tenant state in a shared Redis backend."""

import asyncio
import os

import vaultlet


async def main() -> None:
    """Run the Redis backend example with protected environment configuration."""
    key = vaultlet.MasterKey.from_base64(os.environ["VAULTLET_MASTER_KEY"])
    backend = vaultlet.RedisBackend(
        os.environ["VAULTLET_REDIS_ENDPOINT"],
        namespace=os.environ.get("VAULTLET_REDIS_NAMESPACE", "vaultlet-example"),
        username=os.environ.get("VAULTLET_REDIS_USERNAME"),
        password=os.environ.get("VAULTLET_REDIS_PASSWORD"),
    )
    async with await vaultlet.Vaultlet.open(backend, key=key) as store:
        tenant = store.tenant("customer-123")
        await tenant.set_json("session", {"authenticated": True})
        print(await tenant.get_json("session"))


asyncio.run(main())
