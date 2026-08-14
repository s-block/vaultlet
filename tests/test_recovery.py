"""Crash recovery and malformed-file tests."""

from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import vaultlet


def test_empty_existing_files_recover_initialization(tmp_path: Path) -> None:
    """A provably empty file or SQLite database can complete initialization."""

    async def verify(path: Path) -> None:
        key = vaultlet.MasterKey.generate()
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        await store.tenant("tenant").set("key", b"value")
        await store.aclose()
        reopened = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        assert await reopened.tenant("tenant").get("key") == b"value"
        await reopened.aclose()

    empty_file = tmp_path / "empty-file.vaultlet"
    empty_file.touch()
    asyncio.run(verify(empty_file))

    empty_sqlite = tmp_path / "empty-sqlite.vaultlet"
    sqlite3.connect(empty_sqlite).close()
    asyncio.run(verify(empty_sqlite))

    empty_redb = tmp_path / "empty-redb.vaultlet"
    empty_redb.touch()

    async def verify_redb() -> None:
        key = vaultlet.MasterKey.generate()
        backend = vaultlet.FileBackend(empty_redb, engine=vaultlet.StorageEngine.REDB)
        store = await vaultlet.Vaultlet.open(backend, key=key, cleanup_interval=0)
        await store.tenant("tenant").set("key", b"value")
        await store.aclose()
        reopened = await vaultlet.Vaultlet.open(backend, key=key, cleanup_interval=0)
        assert await reopened.tenant("tenant").keys() == vaultlet.KeyListing(
            keys=("key",), has_more=False
        )
        await reopened.aclose()

    asyncio.run(verify_redb())


def test_non_vaultlet_sqlite_file_fails_closed(tmp_path: Path) -> None:
    """Initialization recovery never claims a database with foreign schema."""
    path = tmp_path / "foreign.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE application_data (value TEXT)")

    async def reopen() -> None:
        with pytest.raises(vaultlet.IntegrityError):
            await vaultlet.Vaultlet.open(
                vaultlet.FileBackend(path),
                key=vaultlet.MasterKey.generate(),
                cleanup_interval=0,
            )

    asyncio.run(reopen())


def test_committed_write_survives_abrupt_exit(tmp_path: Path) -> None:
    """Immediate two-phase commits recover after an unclean process exit."""
    path = tmp_path / "crash.vaultlet"
    key = vaultlet.MasterKey.generate()
    helper = Path(__file__).parent / "helpers" / "crash_writer.py"
    subprocess.run(  # noqa: S603 - interpreter and helper are repository-controlled
        [sys.executable, str(helper), str(path), key.export_base64(), "committed"],
        check=True,
    )

    async def verify() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        assert await store.tenant("tenant").get("committed") == b"survives"
        await store.aclose()

    asyncio.run(verify())


def test_interrupted_batch_recovers_atomically(tmp_path: Path) -> None:
    """Crash recovery exposes either the whole mutation batch or none of it."""
    path = tmp_path / "interrupted.vaultlet"
    key = vaultlet.MasterKey.generate()
    helper = Path(__file__).parent / "helpers" / "crash_writer.py"
    subprocess.run(  # noqa: S603 - interpreter and helper are repository-controlled
        [sys.executable, str(helper), str(path), key.export_base64(), "interrupted"],
        check=True,
    )

    async def verify() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        keys = [f"batch-{index}" for index in range(16)]
        values = await store.tenant("tenant").get_many(keys)
        assert len(values) in {0, len(keys)}
        await store.aclose()

    asyncio.run(verify())


def test_truncated_database_fails_closed(tmp_path: Path) -> None:
    """Storage corruption is never treated as an empty store."""
    path = tmp_path / "truncated.vaultlet"
    key = vaultlet.MasterKey.generate()

    async def create() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        await store.tenant("tenant").set("key", b"value")
        await store.aclose()

    asyncio.run(create())
    contents = path.read_bytes()
    path.write_bytes(contents[: len(contents) // 2])

    async def reopen() -> None:
        with pytest.raises((vaultlet.IntegrityError, vaultlet.UnsupportedFormatError)):
            await vaultlet.Vaultlet.open(
                vaultlet.FileBackend(path), key=key, cleanup_interval=0
            )

    asyncio.run(reopen())


def test_modified_encrypted_record_fails_closed(tmp_path: Path) -> None:
    """A modified record cannot be returned as attacker-controlled plaintext."""
    path = tmp_path / "tampered.vaultlet"
    key = vaultlet.MasterKey.generate()

    async def create() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        await store.tenant("tenant").set("key", b"authenticated value")
        await store.aclose()

    asyncio.run(create())
    contents = bytearray(path.read_bytes())
    envelope = contents.find(b"VLTREC\0\0")
    assert envelope >= 0
    contents[envelope + 107] ^= 1
    path.write_bytes(contents)

    async def read_tampered() -> None:
        store = await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(path), key=key, cleanup_interval=0
        )
        try:
            await store.tenant("tenant").get("key")
        finally:
            await store.aclose()

    with pytest.raises(vaultlet.IntegrityError):
        asyncio.run(read_tampered())
