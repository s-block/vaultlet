"""Public boundary validation tests."""

from __future__ import annotations

import asyncio
import itertools
import math
import pickle
from datetime import datetime
from typing import TYPE_CHECKING, cast

import pytest

import vaultlet


def test_file_backend_engine_is_explicitly_typed(tmp_path: Path) -> None:
    """Backend selection rejects misspelled or untyped engine values."""
    backend = vaultlet.FileBackend(tmp_path / "store")
    assert backend.engine is vaultlet.StorageEngine.SQLITE
    assert (
        vaultlet.FileBackend(
            tmp_path / "redb", engine=vaultlet.StorageEngine.REDB
        ).engine
        is vaultlet.StorageEngine.REDB
    )
    with pytest.raises(TypeError, match="StorageEngine"):
        vaultlet.FileBackend(tmp_path / "invalid", engine="redb")  # type: ignore[arg-type]


def test_redis_backend_configuration_is_typed_and_redacted() -> None:
    """Redis connection settings reject ambiguous inputs and hide passwords."""
    backend = vaultlet.RedisBackend(
        "rediss://redis.example.test:6380/2",
        namespace="application-production",
        username="vaultlet",
        password="do-not-display",
        connect_timeout=2,
        response_timeout=10,
        durability_timeout=3,
    )
    assert backend.endpoint == "rediss://redis.example.test:6380/2"
    assert backend.username == "vaultlet"
    assert backend.connect_timeout == 2
    assert "do-not-display" not in repr(backend)
    assert "<redacted>" in repr(backend)

    for endpoint in (
        "http://redis.example.test",
        "redis://",
        "redis://[",
        "redis://user:password@redis.example.test",
        "redis://redis.example.test:not-a-port",
    ):
        with pytest.raises(vaultlet.ConfigurationError):
            vaultlet.RedisBackend(endpoint, namespace="application")

    with pytest.raises(vaultlet.ConfigurationError, match="namespace"):
        vaultlet.RedisBackend("redis://127.0.0.1:6379", namespace="")
    with pytest.raises(vaultlet.ConfigurationError, match="UTF-8"):
        vaultlet.RedisBackend("redis://127.0.0.1:6379", namespace="\ud800")
    with pytest.raises(vaultlet.ConfigurationError, match="positive"):
        vaultlet.RedisBackend(
            "redis://127.0.0.1:6379", namespace="application", connect_timeout=0
        )
    with pytest.raises(vaultlet.ConfigurationError, match="less than"):
        vaultlet.RedisBackend(
            "redis://127.0.0.1:6379",
            namespace="application",
            response_timeout=5,
            durability_timeout=5,
        )


if TYPE_CHECKING:
    from pathlib import Path


def test_identifiers_ttl_buffers_and_json_are_validated(tmp_path: Path) -> None:
    """Invalid inputs fail before reaching persistent state."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "validation.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        with pytest.raises(vaultlet.ConfigurationError, match="empty"):
            store.tenant("")
        tenant = store.tenant("tenant")
        assert "tenant" not in repr(tenant._native)
        assert not hasattr(tenant._native, "tenant_token")
        assert not hasattr(tenant._native, "aead_key")
        with pytest.raises(TypeError, match="pickled"):
            pickle.dumps(tenant._native)
        with pytest.raises(vaultlet.ConfigurationError, match="mutually exclusive"):
            await tenant.set(
                "key", b"value", ttl=1, expires_at=datetime.now().astimezone()
            )
        with pytest.raises(vaultlet.ConfigurationError, match="timezone-aware"):
            await tenant.set("key", b"value", expires_at=datetime.now())
        with pytest.raises(vaultlet.ConfigurationError, match="finite"):
            await tenant.set("key", b"value", ttl=math.inf)
        with pytest.raises(vaultlet.ConfigurationError, match="non-negative"):
            await tenant.set("key", b"value", ttl=-1)
        with pytest.raises(vaultlet.ConfigurationError, match="contiguous"):
            await tenant.set("key", memoryview(b"abcdef")[::2])
        mutable = bytearray(b"buffer-value")
        await tenant.set("buffer", memoryview(mutable))
        mutable[:] = b"changed-data"
        assert await tenant.get("buffer") == b"buffer-value"
        assert await tenant.get_many(["buffer"]) == {"buffer": b"buffer-value"}
        with pytest.raises(vaultlet.ConfigurationError, match="unique"):
            await tenant.get_many(["key", "key"])
        oversized_batch = {
            f"key-{index}": b"" for index in range(vaultlet.MAX_BATCH_ITEMS + 1)
        }
        with pytest.raises(vaultlet.ConfigurationError, match="more than"):
            await tenant.set_many(oversized_batch)
        with pytest.raises(vaultlet.ConfigurationError, match="more than"):
            await tenant.delete_many(itertools.repeat("key"))

        cycle: list[object] = []
        cycle.append(cycle)
        invalid_json = [
            math.nan,
            1 << 65,
            {1: "value"},
            cycle,
            object(),
        ]
        for value in invalid_json:
            with pytest.raises(vaultlet.SerializationError):
                await tenant.set_json("json", cast("vaultlet.JsonInput", value))
        await store.aclose()

    asyncio.run(scenario())


def test_file_backend_rejects_non_files_and_symlinks(tmp_path: Path) -> None:
    """The file backend rejects unsafe target shapes."""

    async def scenario() -> None:
        key = vaultlet.MasterKey.generate()
        with pytest.raises(vaultlet.ConfigurationError, match="regular file"):
            await vaultlet.Vaultlet.open(
                vaultlet.FileBackend(tmp_path), key=key, cleanup_interval=0
            )

        target = tmp_path / "target"
        target.write_bytes(b"")
        link = tmp_path / "link"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            return
        with pytest.raises(vaultlet.ConfigurationError, match="symbolic"):
            await vaultlet.Vaultlet.open(
                vaultlet.FileBackend(link), key=key, cleanup_interval=0
            )

    asyncio.run(scenario())
