"""Redis integration coverage requiring an explicitly configured test server."""

from __future__ import annotations

import asyncio
import os
import secrets

import pytest

import vaultlet


def _backend(namespace: str) -> vaultlet.RedisBackend:
    endpoint = os.environ.get("VAULTLET_TEST_REDIS_ENDPOINT")
    if endpoint is None:
        pytest.skip("VAULTLET_TEST_REDIS_ENDPOINT is not configured")
    return vaultlet.RedisBackend(
        endpoint,
        namespace=namespace,
        username=os.environ.get("VAULTLET_TEST_REDIS_USERNAME"),
        password=os.environ.get("VAULTLET_TEST_REDIS_PASSWORD"),
    )


def test_redis_round_trip_shared_access_expiry_and_rotation() -> None:
    """Redis preserves the public store contract across independent clients."""

    async def scenario() -> None:
        namespace = f"pytest-{os.getpid()}-{secrets.token_hex(12)}"
        backend = _backend(namespace)
        old_key = vaultlet.MasterKey.generate()
        new_key = vaultlet.MasterKey.generate()
        first = await vaultlet.Vaultlet.open(backend, key=old_key, cleanup_interval=0)
        second = await vaultlet.Vaultlet.open(backend, key=old_key, cleanup_interval=0)
        tenant = first.tenant("customer-1")
        peer = second.tenant("customer-1")

        await tenant.set_many({"alpha": b"one", "beta": b"two"})
        assert await peer.get_many(["beta", "alpha", "missing"]) == {
            "beta": b"two",
            "alpha": b"one",
        }
        await peer.set_json("checkpoint", {"step": 4, "pending": []})
        checkpoint = await tenant.get_json("checkpoint")
        assert isinstance(checkpoint, vaultlet.JsonObject)
        assert checkpoint.to_builtin() == {"step": 4, "pending": []}

        listing = await tenant.keys(limit=10)
        assert set(listing.keys) == {"alpha", "beta", "checkpoint"}
        await tenant.set("expired", b"gone", ttl=0)
        assert await peer.get("expired") is None
        assert await first.purge_expired() >= 0

        await first.rotate_master_key(new_key)
        await first.aclose()
        await second.aclose()

        reopened = await vaultlet.Vaultlet.open(
            backend, key=new_key, cleanup_interval=0
        )
        assert await reopened.tenant("customer-1").get("alpha") == b"one"
        await reopened.aclose()
        with pytest.raises(vaultlet.InvalidKeyError):
            await vaultlet.Vaultlet.open(backend, key=old_key, cleanup_interval=0)

    asyncio.run(scenario())
