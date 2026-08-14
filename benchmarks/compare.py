"""End-to-end workloads for pyperf and labelled comparison stores."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import platform
import secrets
import tempfile
from pathlib import Path
from time import perf_counter
from typing import Literal

import vaultlet

type BackendName = Literal[
    "vaultlet-sqlite",
    "vaultlet-redb",
    "vaultlet-redis",
    "aiosqlite-aead",
    "diskcache",
]
type ScenarioName = Literal["bytes", "json"]


async def vaultlet_backend_bytes(
    backend: vaultlet.FileBackend | vaultlet.RedisBackend,
    *,
    size: int,
    tasks: int,
) -> None:
    """Run durable Vaultlet byte sets, gets, and deletes."""
    store = await vaultlet.Vaultlet.open(
        backend,
        key=vaultlet.MasterKey.generate(),
        cleanup_interval=0,
    )

    async def worker(number: int) -> None:
        tenant = store.tenant(f"tenant-{number}")
        value = bytes(size)
        for iteration in range(20):
            key = f"key-{iteration}"
            await tenant.set(key, value)
            if await tenant.get(key) != value:
                raise RuntimeError("Vaultlet byte benchmark read mismatch")
            if not await tenant.delete(key):
                raise RuntimeError("Vaultlet byte benchmark delete mismatch")

    await asyncio.gather(*(worker(number) for number in range(tasks)))
    await store.aclose()


async def vaultlet_bytes(
    path: Path,
    *,
    engine: vaultlet.StorageEngine,
    size: int,
    tasks: int,
) -> None:
    """Run a durable Vaultlet byte workload on a file backend."""
    await vaultlet_backend_bytes(
        vaultlet.FileBackend(path / f"vaultlet-{engine.value}.db", engine=engine),
        size=size,
        tasks=tasks,
    )


async def vaultlet_backend_json(
    backend: vaultlet.FileBackend | vaultlet.RedisBackend, *, tasks: int
) -> None:
    """Run representative agent-checkpoint JSON batches."""
    store = await vaultlet.Vaultlet.open(
        backend,
        key=vaultlet.MasterKey.generate(),
        cleanup_interval=0,
    )
    checkpoint: vaultlet.JsonInput = {
        "step": 42,
        "messages": [{"role": "user", "content": "status"}] * 20,
        "pending": [],
    }

    async def worker(number: int) -> None:
        tenant = store.tenant(f"tenant-{number}")
        for iteration in range(10):
            await tenant.set_many_json(
                {f"checkpoint-{iteration}": checkpoint, f"writes-{iteration}": []}
            )
            values = await tenant.get_many_json(
                [f"checkpoint-{iteration}", f"writes-{iteration}"]
            )
            if len(values) != 2:
                raise RuntimeError("Vaultlet JSON benchmark read mismatch")

    await asyncio.gather(*(worker(number) for number in range(tasks)))
    await store.aclose()


async def vaultlet_json(
    path: Path, *, engine: vaultlet.StorageEngine, tasks: int
) -> None:
    """Run a durable Vaultlet JSON workload on a file backend."""
    await vaultlet_backend_json(
        vaultlet.FileBackend(path / f"vaultlet-json-{engine.value}.db", engine=engine),
        tasks=tasks,
    )


def redis_backend() -> vaultlet.RedisBackend:
    """Build a unique Redis benchmark namespace from explicit test settings."""
    try:
        endpoint = os.environ["VAULTLET_TEST_REDIS_ENDPOINT"]
    except KeyError as error:
        raise RuntimeError(
            "VAULTLET_TEST_REDIS_ENDPOINT is required for vaultlet-redis"
        ) from error
    return vaultlet.RedisBackend(
        endpoint,
        namespace=f"benchmark-{os.getpid()}-{secrets.token_hex(12)}",
        username=os.environ.get("VAULTLET_TEST_REDIS_USERNAME"),
        password=os.environ.get("VAULTLET_TEST_REDIS_PASSWORD"),
    )


async def aiosqlite_aead_bytes(path: Path, *, size: int, tasks: int) -> None:
    """Run the encrypted Python baseline with full SQLite durability."""
    import aiosqlite
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    database = await aiosqlite.connect(path / "aiosqlite.db")
    await database.execute("PRAGMA journal_mode=WAL")
    await database.execute("PRAGMA synchronous=FULL")
    await database.execute(
        "CREATE TABLE records (record_id BLOB PRIMARY KEY, value BLOB NOT NULL)"
    )
    await database.commit()
    master_key = os.urandom(32)
    cipher = AESGCM(master_key)

    async def worker(number: int) -> None:
        tenant = f"tenant-{number}"
        value = bytes(size)
        for iteration in range(20):
            record_id = hmac.digest(
                master_key, f"{tenant}\0key-{iteration}".encode(), hashlib.sha256
            )
            nonce = os.urandom(12)
            ciphertext = nonce + cipher.encrypt(nonce, value, record_id)
            await database.execute(
                "INSERT OR REPLACE INTO records VALUES (?, ?)",
                (record_id, ciphertext),
            )
            await database.commit()
            async with database.execute(
                "SELECT value FROM records WHERE record_id = ?", (record_id,)
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                raise RuntimeError("aiosqlite baseline read missed")
            stored = bytes(row[0])
            if cipher.decrypt(stored[:12], stored[12:], record_id) != value:
                raise RuntimeError("aiosqlite baseline read mismatch")
            await database.execute(
                "DELETE FROM records WHERE record_id = ?", (record_id,)
            )
            await database.commit()

    await asyncio.gather(*(worker(number) for number in range(tasks)))
    await database.close()


async def diskcache_bytes(path: Path, *, size: int, tasks: int) -> None:
    """Run an explicitly unencrypted local-cache comparison."""
    from diskcache import Cache  # type: ignore[import-untyped]

    cache = Cache(str(path / "diskcache"))

    async def worker(number: int) -> None:
        value = bytes(size)
        for iteration in range(20):
            key = f"tenant-{number}\0key-{iteration}"
            await asyncio.to_thread(cache.set, key, value)
            observed = await asyncio.to_thread(cache.get, key)
            if observed != value:
                raise RuntimeError("DiskCache comparison read mismatch")
            await asyncio.to_thread(cache.delete, key)

    await asyncio.gather(*(worker(number) for number in range(tasks)))
    cache.close()


def run_once(
    backend: BackendName,
    scenario: ScenarioName,
    *,
    size: int,
    tasks: int,
) -> float:
    """Run one timed scenario in a fresh directory."""
    if scenario == "json" and not backend.startswith("vaultlet-"):
        raise ValueError("the JSON scenario currently measures Vaultlet only")
    with tempfile.TemporaryDirectory(prefix="vaultlet-bench-") as directory:
        path = Path(directory)
        started = perf_counter()
        if backend == "vaultlet-redis":
            configured = redis_backend()
            if scenario == "json":
                asyncio.run(vaultlet_backend_json(configured, tasks=tasks))
            else:
                asyncio.run(vaultlet_backend_bytes(configured, size=size, tasks=tasks))
        elif backend.startswith("vaultlet-"):
            engine = (
                vaultlet.StorageEngine.SQLITE
                if backend == "vaultlet-sqlite"
                else vaultlet.StorageEngine.REDB
            )
            if scenario == "json":
                asyncio.run(vaultlet_json(path, engine=engine, tasks=tasks))
            else:
                asyncio.run(vaultlet_bytes(path, engine=engine, size=size, tasks=tasks))
        elif backend == "aiosqlite-aead":
            asyncio.run(aiosqlite_aead_bytes(path, size=size, tasks=tasks))
        else:
            asyncio.run(diskcache_bytes(path, size=size, tasks=tasks))
        return perf_counter() - started


def main() -> None:
    """Emit one JSON result for measurement by ``pyperf command``."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "backend",
        choices=(
            "vaultlet-sqlite",
            "vaultlet-redb",
            "vaultlet-redis",
            "aiosqlite-aead",
            "diskcache",
        ),
    )
    parser.add_argument("scenario", choices=("bytes", "json"))
    parser.add_argument("--size", type=int, default=4096)
    parser.add_argument("--tasks", type=int, choices=(1, 8, 32), default=1)
    arguments = parser.parse_args()
    backend = arguments.backend
    scenario = arguments.scenario
    elapsed = run_once(backend, scenario, size=arguments.size, tasks=arguments.tasks)
    print(
        json.dumps(
            {
                "backend": backend,
                "scenario": scenario,
                "size": arguments.size,
                "tasks": arguments.tasks,
                "elapsed_seconds": elapsed,
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
