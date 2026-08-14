"""Encrypted store integration tests."""

from __future__ import annotations

import asyncio
import gc
import os
import stat
import subprocess
import sys
import time
import tracemalloc
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import vaultlet


def test_bytes_reopen_metadata_and_tenant_isolation(tmp_path: Path) -> None:
    """Byte records persist and equal names stay tenant-scoped."""

    async def scenario() -> None:
        path = tmp_path / "state.vaultlet"
        key = vaultlet.MasterKey.generate()
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        first = store.tenant("customer-a")
        second = store.tenant("customer-b")

        await first.set("api-credential", bytearray(b"alpha"))
        await second.set("api-credential", memoryview(b"bravo"))
        assert await first.get("api-credential") == b"alpha"
        assert await second.get("api-credential") == b"bravo"
        assert await first.exists("api-credential")
        assert await first.metadata("api-credential") == vaultlet.EntryMetadata(
            kind=vaultlet.ValueKind.BYTES,
            encoded_size=5,
            expires_at=None,
        )
        await store.aclose()

        reopened = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        assert await reopened.tenant("customer-a").get("api-credential") == b"alpha"
        assert await reopened.tenant("customer-b").get("api-credential") == b"bravo"
        await reopened.aclose()

        raw = path.read_bytes()
        for plaintext in (
            b"customer-a",
            b"customer-b",
            b"api-credential",
            b"alpha",
            b"bravo",
        ):
            assert plaintext not in raw

        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600

    asyncio.run(scenario())


def test_json_and_kind_safety(tmp_path: Path) -> None:
    """JSON has a strict explicit codec and cannot be confused with bytes."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "json.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        value: vaultlet.JsonInput = {
            "bool": True,
            "float": 2.5,
            "int": (1 << 64) - 1,
            "list": [None, "text"],
        }
        await tenant.set_json("checkpoint", value)
        checkpoint = await tenant.get_json("checkpoint")
        assert checkpoint == value
        assert isinstance(checkpoint, Mapping)
        assert isinstance(checkpoint, vaultlet.JsonObject)
        assert not isinstance(checkpoint, dict)
        assert checkpoint.get("int") == (1 << 64) - 1
        assert checkpoint.get("missing", "default") == "default"
        assert list(checkpoint) == ["bool", "float", "int", "list"]
        items = checkpoint["list"]
        assert isinstance(items, Sequence)
        assert isinstance(items, vaultlet.JsonArray)
        assert not isinstance(items, list)
        assert items[0] is None
        assert items[-1] == "text"
        assert items[:] == (None, "text")
        assert items.count("text") == 1
        assert items.index("text") == 1
        assert checkpoint.to_builtin() == value
        with pytest.raises(TypeError):
            checkpoint["int"] = 1  # type: ignore[index]
        with pytest.raises(TypeError):
            items[0] = "changed"  # type: ignore[index]
        await tenant.set_json("checkpoint-copy", checkpoint)
        assert await tenant.get_json("checkpoint-copy") == value
        with pytest.raises(vaultlet.TypeMismatchError):
            await tenant.get("checkpoint")

        await tenant.set("opaque", b"{}")
        with pytest.raises(vaultlet.TypeMismatchError):
            await tenant.get_json("opaque")
        await store.aclose()

    asyncio.run(scenario())


def test_json_read_allocations_are_lazy(tmp_path: Path) -> None:
    """Node-heavy JSON reads do not eagerly build a Python object graph."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "json-allocation.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        await tenant.set_json("small", {"field": 1})
        await tenant.set_json(
            "large", {f"field-{index}": index for index in range(20_000)}
        )

        async def peak_for(key: str) -> int:
            gc.collect()
            tracemalloc.start()
            tracemalloc.reset_peak()
            value = await tenant.get_json(key)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert isinstance(value, Mapping)
            return peak

        small_peak = await peak_for("small")
        large_peak = await peak_for("large")
        assert large_peak <= small_peak + 64 * 1024
        await store.aclose()

    asyncio.run(scenario())


def test_metadata_never_reconstructs_plaintext_in_python(tmp_path: Path) -> None:
    """Metadata's Python allocation stays independent of stored value size."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "metadata-allocation.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        await tenant.set("small", bytes(64))
        await tenant.set("large", bytes(10 * 1024 * 1024))

        async def peak_for(key: str) -> int:
            gc.collect()
            tracemalloc.start()
            tracemalloc.reset_peak()
            metadata = await tenant.metadata(key)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert metadata is not None
            return peak

        small_peak = await peak_for("small")
        large_peak = await peak_for("large")
        assert large_peak <= small_peak + 64 * 1024
        await store.aclose()

    asyncio.run(scenario())


def test_atomic_bulk_crud_and_order(tmp_path: Path) -> None:
    """Bulk writes are atomic and snapshot reads preserve requested order."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "bulk.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        await tenant.set_many({"a": b"1", "b": b"2", "c": b"3"})
        assert await tenant.get_many(["c", "missing", "a"]) == {
            "c": b"3",
            "a": b"1",
        }
        await tenant.set_many_json({"one": {"n": 1}, "two": [2]})
        assert await tenant.get_many_json(["two", "one"]) == {
            "two": [2],
            "one": {"n": 1},
        }
        assert await tenant.delete_many(["a", "missing", "c"]) == 2
        assert await tenant.get_many(["a", "b", "c"]) == {"b": b"2"}
        assert await tenant.delete("b")
        assert not await tenant.delete("b")
        await store.aclose()

    asyncio.run(scenario())


def test_ttl_lazy_and_explicit_cleanup(tmp_path: Path) -> None:
    """Expired records are hidden immediately and removed by maintenance."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "ttl.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        await tenant.set("past", b"gone", expires_at=datetime.now(UTC) - timedelta(1))
        assert await tenant.get("past") is None
        await tenant.set_json("expired-json", {"gone": True}, ttl=0)
        assert await tenant.get("expired-json") is None

        expires = datetime.now(UTC) + timedelta(milliseconds=40)
        await tenant.set("soon", b"value", expires_at=expires)
        metadata = await tenant.metadata("soon")
        assert metadata is not None
        assert metadata.expires_at is not None
        assert abs((metadata.expires_at - expires).total_seconds()) < 0.002
        await asyncio.sleep(0.06)
        assert await store.purge_expired() == 1
        assert await tenant.get("soon") is None

        batch_expiry = datetime.now(UTC) + timedelta(milliseconds=30)
        await tenant.set_many(
            {f"expired-{index}": b"value" for index in range(40)},
            expires_at=batch_expiry,
        )
        await asyncio.sleep(0.05)
        assert await store.purge_expired() == 40
        await store.aclose()

        background = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "background.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0.01,
        )
        await background.tenant("tenant").set("soon", b"value", ttl=0.01)
        await asyncio.sleep(0.1)
        assert await background.purge_expired() == 0
        await background.aclose()

        overwrite_path = tmp_path / "ttl-overwrite.vaultlet"
        overwrite_key = vaultlet.MasterKey.generate()
        overwrite = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(overwrite_path),
            key=overwrite_key,
            cleanup_interval=0,
        )
        overwrite_tenant = overwrite.tenant("tenant")
        await overwrite_tenant.set("key", b"old", ttl=0.01)
        await overwrite_tenant.set("key", b"current")
        await asyncio.sleep(0.03)
        assert await overwrite.purge_expired() == 0
        assert await overwrite_tenant.get("key") == b"current"
        await overwrite.aclose()

        reopened = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(overwrite_path),
            key=overwrite_key,
            cleanup_interval=0,
        )
        assert await reopened.tenant("tenant").get("key") == b"current"
        await reopened.aclose()

    asyncio.run(scenario())


def test_shared_open_wrong_key_and_closed_state(tmp_path: Path) -> None:
    """Shared ownership, key confirmation, and use-after-close are explicit."""

    async def scenario() -> None:
        path = tmp_path / "lifecycle.vaultlet"
        key = vaultlet.MasterKey.generate()
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        shared = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        await shared.tenant("tenant").set("shared", b"visible")
        assert await store.tenant("tenant").get("shared") == b"visible"
        await shared.aclose()
        tenant = store.tenant("tenant")
        await asyncio.gather(store.aclose(), store.aclose())
        assert store.closed
        await store.aclose()
        with pytest.raises(vaultlet.ClosedError):
            store.tenant("other")
        with pytest.raises(vaultlet.ClosedError):
            await tenant.get("key")

        with pytest.raises(vaultlet.InvalidKeyError):
            await vaultlet.Vaultlet.open(
                vaultlet.FileBackend(path),
                key=vaultlet.MasterKey.generate(),
                cleanup_interval=0,
            )

    asyncio.run(scenario())


def test_enumeration_is_tenant_scoped_atomic_and_expiry_aware(tmp_path: Path) -> None:
    """Catalogue reads stay tenant-scoped and observe whole mutation batches."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "keys.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        other = store.tenant("other")
        await tenant.set_many({"bravo": b"2", "alpha": b"1"})
        await other.set("private", b"3")
        await tenant.set("expired", b"gone", ttl=0)
        assert await tenant.keys() == vaultlet.KeyListing(
            keys=("alpha", "bravo"), has_more=False
        )
        assert await other.keys() == vaultlet.KeyListing(
            keys=("private",), has_more=False
        )

        batch = [f"batch-{index}" for index in range(24)]
        finished = False

        async def writer() -> None:
            nonlocal finished
            try:
                for _ in range(20):
                    await tenant.set_many(dict.fromkeys(batch, b"value"))
                    await tenant.delete_many(batch)
            finally:
                finished = True

        async def reader() -> None:
            while not finished:
                observed = (await tenant.keys()).keys
                batch_count = sum(key.startswith("batch-") for key in observed)
                assert batch_count in {0, len(batch)}

        await asyncio.gather(writer(), reader())
        assert await tenant.delete("alpha")
        assert await tenant.keys() == vaultlet.KeyListing(
            keys=("bravo",), has_more=False
        )
        await store.aclose()

    asyncio.run(scenario())


def test_enumeration_limit_is_bounded_and_reports_lookahead(tmp_path: Path) -> None:
    """Key enumeration validates limits and reports a truncated catalogue."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "bounded-keys.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        expected = {"alpha", "bravo", "charlie"}
        await tenant.set_many(dict.fromkeys(expected, b"value"))

        bounded = await tenant.keys(limit=2)
        assert len(bounded.keys) == 2
        assert bounded.keys == tuple(sorted(bounded.keys))
        assert set(bounded.keys) < expected
        assert bounded.has_more
        assert bounded.next_cursor is not None

        remaining = await tenant.keys(limit=2, cursor=bounded.next_cursor)
        assert set(bounded.keys) | set(remaining.keys) == expected
        assert set(bounded.keys).isdisjoint(remaining.keys)
        assert not remaining.has_more
        assert remaining.next_cursor is None

        complete = await tenant.keys(limit=3)
        assert complete == vaultlet.KeyListing(
            keys=("alpha", "bravo", "charlie"), has_more=False
        )

        for invalid in (True, 1.5, "1"):
            with pytest.raises(TypeError):
                await tenant.keys(limit=invalid)  # type: ignore[arg-type]
        for invalid in (0, -1, vaultlet.MAX_KEY_LIST_LIMIT + 1):
            with pytest.raises(vaultlet.ConfigurationError):
                await tenant.keys(limit=invalid)
        with pytest.raises(TypeError, match="cursor"):
            await tenant.keys(cursor=1)  # type: ignore[arg-type]
        with pytest.raises(vaultlet.ConfigurationError, match="cursor"):
            await tenant.keys(cursor="not-a-cursor")
        with pytest.raises(vaultlet.ConfigurationError, match="store and tenant"):
            await store.tenant("other").keys(cursor=bounded.next_cursor)
        replacement = "A" if bounded.next_cursor[-1] != "A" else "B"
        with pytest.raises(vaultlet.ConfigurationError, match="cursor"):
            await tenant.keys(cursor=f"{bounded.next_cursor[:-1]}{replacement}")

        other_store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "other-keys.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        with pytest.raises(vaultlet.ConfigurationError, match="store and tenant"):
            await other_store.tenant("tenant").keys(cursor=bounded.next_cursor)
        await other_store.aclose()
        await store.aclose()

    asyncio.run(scenario())


def test_master_key_rotation_preserves_open_processes_and_data(tmp_path: Path) -> None:
    """Rotation rewraps the store key without rewriting encrypted records."""

    async def scenario() -> None:
        path = tmp_path / "rotation.vaultlet"
        old_key = vaultlet.MasterKey.generate()
        new_key = vaultlet.MasterKey.generate()
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=old_key, cleanup_interval=0
        )
        await store.tenant("tenant").set("profile", b"encrypted")
        await store.rotate_master_key(new_key)
        assert await store.tenant("tenant").get("profile") == b"encrypted"

        reopened = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=new_key, cleanup_interval=0
        )
        assert await reopened.tenant("tenant").keys() == vaultlet.KeyListing(
            keys=("profile",), has_more=False
        )
        await reopened.tenant("tenant").set("second", b"value")
        assert await store.tenant("tenant").get("second") == b"value"
        await reopened.aclose()
        await store.aclose()

        with pytest.raises(vaultlet.InvalidKeyError):
            await vaultlet.Vaultlet.open(
                vaultlet.FileBackend(path), key=old_key, cleanup_interval=0
            )

        final = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=new_key, cleanup_interval=0
        )
        assert await final.tenant("tenant").get_many(["profile", "second"]) == {
            "profile": b"encrypted",
            "second": b"value",
        }
        await final.aclose()

    asyncio.run(scenario())


def test_multiple_processes_initialize_and_mutate_one_store(tmp_path: Path) -> None:
    """Independent processes can overlap and commit complete catalogue batches."""
    path = tmp_path / "processes.vaultlet"
    key = vaultlet.MasterKey.generate()
    helper = Path(__file__).parent / "helpers" / "multi_process_writer.py"
    release = tmp_path / "release"
    process_count = 6
    batch_size = 20
    processes: list[subprocess.Popen[str]] = []
    for process_index in range(process_count):
        ready = tmp_path / f"ready-{process_index}"
        processes.append(
            subprocess.Popen(  # noqa: S603 - interpreter and helper are controlled
                [
                    sys.executable,
                    str(helper),
                    str(path),
                    key.export_base64(),
                    str(ready),
                    str(release),
                    f"process-{process_index}",
                    str(batch_size),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        )

    deadline = time.monotonic() + 40
    ready_files = [tmp_path / f"ready-{index}" for index in range(process_count)]
    while not all(ready.exists() for ready in ready_files):
        if time.monotonic() >= deadline:
            release.touch()
            outputs = [process.communicate(timeout=10) for process in processes]
            pytest.fail(f"processes did not overlap successfully: {outputs!r}")
        time.sleep(0.01)
    release.touch()
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, (stdout, stderr)

    async def verify() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        tenant = store.tenant("tenant")
        expected = [
            f"process-{process_index}-{item_index}"
            for process_index in range(process_count)
            for item_index in range(batch_size)
        ]
        assert await tenant.keys() == vaultlet.KeyListing(
            keys=tuple(sorted(expected)), has_more=False
        )
        assert len(await tenant.get_many(expected)) == len(expected)
        await store.aclose()

    asyncio.run(verify())


def test_redb_feature_parity_and_exclusive_ownership(tmp_path: Path) -> None:
    """The redb option supports data features while retaining its native lock."""

    async def scenario() -> None:
        path = tmp_path / "exclusive.vaultlet"
        backend = vaultlet.FileBackend(path, engine=vaultlet.StorageEngine.REDB)
        key = vaultlet.MasterKey.generate()
        replacement = vaultlet.MasterKey.generate()
        store = await vaultlet.Vaultlet.open(backend, key=key, cleanup_interval=0)
        tenant = store.tenant("tenant")
        await tenant.set_many({"alpha": b"1", "bravo": b"2"})
        assert await tenant.keys() == vaultlet.KeyListing(
            keys=("alpha", "bravo"), has_more=False
        )
        with pytest.raises(vaultlet.StoreLockedError):
            await vaultlet.Vaultlet.open(backend, key=key, cleanup_interval=0)
        await store.rotate_master_key(replacement)
        await store.aclose()

        reopened = await vaultlet.Vaultlet.open(
            backend, key=replacement, cleanup_interval=0
        )
        assert await reopened.tenant("tenant").get_many(["bravo", "alpha"]) == {
            "bravo": b"2",
            "alpha": b"1",
        }
        assert await reopened.tenant("tenant").delete("alpha")
        assert await reopened.tenant("tenant").keys() == vaultlet.KeyListing(
            keys=("bravo",), has_more=False
        )
        await reopened.aclose()

    asyncio.run(scenario())


def test_async_context_and_concurrent_access(tmp_path: Path) -> None:
    """Mixed readers and writers progress without blocking the Python loop."""

    async def scenario() -> None:
        ticks = 0
        running = True

        async def ticker() -> None:
            nonlocal ticks
            while running:
                ticks += 1
                await asyncio.sleep(0)

        async with await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "concurrent.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        ) as store:
            tenant = store.tenant("tenant")
            ticker_task = asyncio.create_task(ticker())

            async def writer(number: int) -> None:
                await tenant.set(f"key-{number}", bytes(256 * 1024))

            await asyncio.gather(*(writer(number) for number in range(16)))
            values = await tenant.get_many(f"key-{number}" for number in range(16))
            running = False
            await ticker_task
            assert len(values) == 16
            assert ticks > 10
        assert store.closed

    asyncio.run(scenario())


def test_concurrent_batch_visibility_and_same_key_writes(tmp_path: Path) -> None:
    """Readers see complete batches and racing values remain intact."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "atomic-visibility.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        keys = [f"key-{index}" for index in range(16)]
        await tenant.set_many(dict.fromkeys(keys, b"initial"))
        finished = False

        async def writer() -> None:
            nonlocal finished
            try:
                for iteration in range(12):
                    value = f"batch-{iteration}".encode()
                    await tenant.set_many(dict.fromkeys(keys, value))
            finally:
                finished = True

        async def reader() -> None:
            while not finished:
                observed = await tenant.get_many(keys)
                assert len(observed) == len(keys)
                assert len(set(observed.values())) == 1

        await asyncio.gather(writer(), reader())

        candidates = {f"writer-{index}".encode() for index in range(24)}
        await asyncio.gather(*(tenant.set("shared", value) for value in candidates))
        assert await tenant.get("shared") in candidates
        await store.aclose()

    asyncio.run(scenario())


def test_cancellation_never_exposes_partial_values(tmp_path: Path) -> None:
    """A cancelled write is either absent or committed in full."""

    async def scenario() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(tmp_path / "cancel.vaultlet"),
            key=vaultlet.MasterKey.generate(),
            cleanup_interval=0,
        )
        tenant = store.tenant("tenant")
        before_dispatch = asyncio.create_task(tenant.set("cancelled-early", b"value"))
        before_dispatch.cancel()
        with pytest.raises(asyncio.CancelledError):
            await before_dispatch
        assert await tenant.get("cancelled-early") is None

        value = bytes(8 * 1024 * 1024)
        task = asyncio.create_task(tenant.set("large", value))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        observed = await tenant.get("large")
        assert observed is None or observed == value
        await store.aclose()

    asyncio.run(scenario())


def test_close_waits_for_in_flight_write(tmp_path: Path) -> None:
    """Close drains an operation that entered before closing began."""

    async def scenario() -> None:
        path = tmp_path / "close-in-flight.vaultlet"
        key = vaultlet.MasterKey.generate()
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        value = bytes(16 * 1024 * 1024)
        write = asyncio.create_task(store.tenant("tenant").set("large", value))
        await asyncio.sleep(0)
        await asyncio.gather(write, store.aclose())

        reopened = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        assert await reopened.tenant("tenant").get("large") == value
        await reopened.aclose()

    asyncio.run(scenario())
