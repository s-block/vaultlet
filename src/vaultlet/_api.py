"""Typed Python facade over Vaultlet's private native module."""

from __future__ import annotations

import asyncio
import math
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Never, Self, cast
from urllib.parse import urlsplit

from . import _vaultlet
from ._errors import ClosedError, ConfigurationError
from ._types import (
    MAX_KEY_LIST_LIMIT,
    EntryMetadata,
    JsonInput,
    JsonValue,
    KeyListing,
    Seconds,
    StorageEngine,
    ValueKind,
)

if TYPE_CHECKING:
    from collections.abc import Buffer, Iterable, Mapping

_BYTES_KIND = 1
_JSON_KIND = 2
_MAX_EPOCH_MS = 253_402_300_799_999
_DEFAULT_KEY_LIST_LIMIT = 1_000


class MasterKey:
    """A redacted, zeroizing 256-bit key supplied by the application."""

    __slots__ = ("_native",)

    _native: _vaultlet._NativeMasterKey

    def __new__(cls) -> Self:
        raise TypeError("use MasterKey.generate(), from_bytes(), or from_base64()")

    @classmethod
    def _from_native(cls, native: _vaultlet._NativeMasterKey) -> Self:
        instance = object.__new__(cls)
        instance._native = native
        return instance

    @classmethod
    def generate(cls) -> Self:
        """Generate a new key using the operating system CSPRNG."""
        return cls._from_native(_vaultlet._NativeMasterKey.generate())

    @classmethod
    def from_bytes(cls, value: Buffer) -> Self:
        """Import exactly 32 key bytes."""
        return cls._from_native(_vaultlet._NativeMasterKey.from_bytes(value))

    @classmethod
    def from_base64(cls, value: str) -> Self:
        """Import a standard Base64-encoded 32-byte key."""
        if not isinstance(value, str):
            raise TypeError("master key must be a Base64 string")
        return cls._from_native(_vaultlet._NativeMasterKey.from_base64(value))

    def export_bytes(self) -> bytes:
        """Export key bytes for explicit provisioning or backup."""
        return self._native.export_bytes()

    def export_base64(self) -> str:
        """Export a standard Base64 representation for explicit provisioning."""
        return self._native.export_base64()

    def __repr__(self) -> str:
        return "MasterKey(<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("MasterKey objects cannot be pickled")


@dataclass(frozen=True, slots=True, init=False)
class FileBackend:
    """Configuration for a local encrypted file backend."""

    path: Path
    engine: StorageEngine

    def __init__(
        self,
        path: os.PathLike[str] | str,
        *,
        engine: StorageEngine = StorageEngine.SQLITE,
    ) -> None:
        try:
            normalized = Path(path)
        except TypeError as error:
            raise TypeError("backend path must be path-like") from error
        if "\0" in os.fspath(normalized):
            raise ConfigurationError("backend path cannot contain a null byte")
        if not isinstance(engine, StorageEngine):
            raise TypeError("engine must be a StorageEngine")
        object.__setattr__(self, "path", normalized)
        object.__setattr__(self, "engine", engine)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RedisBackend:
    """Configuration for one encrypted store in Redis 7.2 or newer.

    ``redis://`` uses a plaintext connection and ``rediss://`` uses TLS with bundled
    public Web PKI trust roots. Credentials are supplied separately so they are never
    retained in the endpoint or included in this object's representation.
    """

    endpoint: str
    namespace: str
    username: str | None
    password: str | None
    connect_timeout: float
    response_timeout: float
    durability_timeout: float

    def __init__(
        self,
        endpoint: str,
        *,
        namespace: str,
        username: str | None = None,
        password: str | None = None,
        connect_timeout: Seconds | timedelta = 5.0,
        response_timeout: Seconds | timedelta = 30.0,
        durability_timeout: Seconds | timedelta = 5.0,
    ) -> None:
        if not isinstance(endpoint, str):
            raise TypeError("Redis endpoint must be a string")
        if "\0" in endpoint:
            raise ConfigurationError("Redis endpoint cannot contain a null byte")
        try:
            parsed = urlsplit(endpoint)
        except ValueError as error:
            raise ConfigurationError("Redis endpoint is invalid") from error
        if parsed.scheme not in {"redis", "rediss"} or parsed.hostname is None:
            raise ConfigurationError(
                "Redis endpoint must use redis:// or rediss:// with a hostname"
            )
        if parsed.username is not None or parsed.password is not None:
            raise ConfigurationError(
                "Redis credentials must be supplied separately from the endpoint"
            )
        try:
            _ = parsed.port
        except ValueError as error:
            raise ConfigurationError("Redis endpoint has an invalid port") from error
        if not isinstance(namespace, str):
            raise TypeError("Redis namespace must be a string")
        try:
            encoded_namespace = namespace.encode()
        except UnicodeEncodeError as error:
            raise ConfigurationError("Redis namespace must be valid UTF-8") from error
        if not namespace or "\0" in namespace or len(encoded_namespace) > 1024:
            raise ConfigurationError(
                "Redis namespace must contain between 1 and 1024 UTF-8 bytes"
            )
        if username is not None and not isinstance(username, str):
            raise TypeError("Redis username must be a string or None")
        if password is not None and not isinstance(password, str):
            raise TypeError("Redis password must be a string or None")
        connect_timeout_ms = _positive_duration_ms(
            connect_timeout, name="connect_timeout"
        )
        response_timeout_ms = _positive_duration_ms(
            response_timeout, name="response_timeout"
        )
        durability_timeout_ms = _positive_duration_ms(
            durability_timeout, name="durability_timeout"
        )
        if durability_timeout_ms >= response_timeout_ms:
            raise ConfigurationError(
                "durability_timeout must be less than response_timeout"
            )
        object.__setattr__(self, "endpoint", endpoint)
        object.__setattr__(self, "namespace", namespace)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password)
        object.__setattr__(self, "connect_timeout", connect_timeout_ms / 1000)
        object.__setattr__(self, "response_timeout", response_timeout_ms / 1000)
        object.__setattr__(self, "durability_timeout", durability_timeout_ms / 1000)

    def __repr__(self) -> str:
        password = "<redacted>" if self.password is not None else "None"
        return (
            "RedisBackend("
            f"endpoint={self.endpoint!r}, namespace={self.namespace!r}, "
            f"username={self.username!r}, password={password}, "
            f"connect_timeout={self.connect_timeout!r}, "
            f"response_timeout={self.response_timeout!r}, "
            f"durability_timeout={self.durability_timeout!r})"
        )


class Vaultlet:
    """Lifecycle owner for one open encrypted store."""

    __slots__ = ("_native",)

    def __init__(self, native: _vaultlet._NativeStore) -> None:
        self._native = native

    @classmethod
    async def open(
        cls,
        backend: FileBackend | RedisBackend,
        *,
        key: MasterKey,
        cleanup_interval: Seconds | timedelta = 60.0,
    ) -> Self:
        """Open or create a store and verify the supplied master key."""
        if not isinstance(backend, (FileBackend, RedisBackend)):
            raise TypeError("backend must be a FileBackend or RedisBackend")
        if not isinstance(key, MasterKey):
            raise TypeError("key must be a MasterKey")
        interval_ms = _duration_ms(cleanup_interval, name="cleanup_interval")
        if isinstance(backend, FileBackend):
            native = await _vaultlet.open_store(
                os.fspath(backend.path), key._native, interval_ms, backend.engine.value
            )
        else:
            native = await _vaultlet.open_redis_store(
                backend.endpoint,
                backend.namespace,
                (backend.username, backend.password),
                key._native,
                interval_ms,
                (
                    round(backend.connect_timeout * 1000),
                    round(backend.response_timeout * 1000),
                    round(backend.durability_timeout * 1000),
                ),
            )
        return cls(native)

    @property
    def closed(self) -> bool:
        """Whether closing has begun."""
        return self._native.closed

    def tenant(self, tenant_id: str) -> TenantStore:
        """Return a tenant-scoped handle.

        Tenant handles prevent accidental cross-tenant calls. Applications remain
        responsible for authentication and mapping callers to trusted, stable tenant
        IDs that are independent of rotating credentials.
        """
        self._ensure_open()
        return TenantStore(self._native.tenant(tenant_id))

    async def purge_expired(self) -> int:
        """Authenticate and physically remove all records currently expired."""
        self._ensure_open()
        return await self._native.purge_expired()

    async def rotate_master_key(self, new_key: MasterKey) -> None:
        """Atomically replace the master key that opens this store."""
        self._ensure_open()
        if not isinstance(new_key, MasterKey):
            raise TypeError("new_key must be a MasterKey")
        await self._native.rotate_master_key(new_key._native)

    async def aclose(self) -> None:
        """Stop maintenance, await in-flight work, and release backend resources."""
        if self.closed:
            await self._native.close()
            return
        close = asyncio.ensure_future(self._native.close())
        try:
            await asyncio.shield(close)
        except asyncio.CancelledError:
            await asyncio.shield(close)
            raise

    async def __aenter__(self) -> Self:
        self._ensure_open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None:
        await self.aclose()

    def _ensure_open(self) -> None:
        if self.closed:
            raise ClosedError("the Vaultlet store is closed")


class TenantStore:
    """All data operations for exactly one tenant."""

    __slots__ = ("_native",)

    def __init__(self, native: _vaultlet._NativeTenant) -> None:
        self._native = native

    async def set(
        self,
        key: str,
        value: Buffer,
        *,
        ttl: Seconds | timedelta | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        """Atomically set one byte value."""
        expiry = _expiry_ms(ttl, expires_at)
        await self._native.set(key, value, expiry)

    async def get(self, key: str) -> bytes | None:
        """Get one byte value, or ``None`` when absent or expired."""
        return await self._native.get(key)

    async def set_json(
        self,
        key: str,
        value: JsonInput,
        *,
        ttl: Seconds | timedelta | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        """Atomically encode and set one JSON value without pickle."""
        expiry = _expiry_ms(ttl, expires_at)
        await self._native.set_json(key, value, expiry)

    async def get_json(self, key: str) -> JsonValue | None:
        """Get and decode one JSON value, or ``None`` when absent or expired."""
        return cast("JsonValue | None", await self._native.get_json(key))

    async def delete(self, key: str) -> bool:
        """Delete one value and report whether it was live."""
        return await self._native.delete(key)

    async def exists(self, key: str) -> bool:
        """Return whether one live value exists."""
        return await self._native.exists(key)

    async def metadata(self, key: str) -> EntryMetadata | None:
        """Authenticate one record and return its metadata."""
        metadata = await self._native.metadata(key)
        if metadata is None:
            return None
        kind, encoded_size, expires_at_ms = metadata
        return EntryMetadata(
            kind=_value_kind(kind),
            encoded_size=encoded_size,
            expires_at=_datetime_from_ms(expires_at_ms),
        )

    async def set_many(
        self,
        values: Mapping[str, Buffer],
        *,
        ttl: Seconds | timedelta | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        """Atomically set a mapping of byte values."""
        expiry = _expiry_ms(ttl, expires_at)
        await self._native.set_many(values, expiry)

    async def get_many(self, keys: Iterable[str]) -> dict[str, bytes]:
        """Read byte values from one storage snapshot, preserving input order."""
        return await self._native.get_many(keys)

    async def set_many_json(
        self,
        values: Mapping[str, JsonInput],
        *,
        ttl: Seconds | timedelta | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        """Atomically encode and set a mapping of JSON values."""
        expiry = _expiry_ms(ttl, expires_at)
        await self._native.set_many_json(values, expiry)

    async def get_many_json(self, keys: Iterable[str]) -> dict[str, JsonValue]:
        """Read JSON values from one storage snapshot, preserving input order."""
        return cast("dict[str, JsonValue]", await self._native.get_many_json(keys))

    async def delete_many(self, keys: Iterable[str]) -> int:
        """Atomically delete keys and return the number of live values removed."""
        return await self._native.delete_many(keys)

    async def keys(
        self,
        *,
        limit: int = _DEFAULT_KEY_LIST_LIMIT,
        cursor: str | None = None,
    ) -> KeyListing:
        """Return one page of live tenant keys, sorted within the page.

        The default limit is 1,000 and the package maximum is
        ``MAX_KEY_LIST_LIMIT``. Pass a page's ``next_cursor`` to continue its
        catalogue scan. Cursors are opaque and scoped to this store and tenant.
        """
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= MAX_KEY_LIST_LIMIT:
            raise ConfigurationError(
                f"limit must be between 1 and {MAX_KEY_LIST_LIMIT}"
            )
        if cursor is not None and not isinstance(cursor, str):
            raise TypeError("cursor must be a string or None")
        keys, has_more, next_cursor = await self._native.keys(limit, cursor)
        return KeyListing(keys=tuple(keys), has_more=has_more, next_cursor=next_cursor)


def _expiry_ms(
    ttl: Seconds | timedelta | None, expires_at: datetime | None
) -> int | None:
    if ttl is not None and expires_at is not None:
        raise ConfigurationError("ttl and expires_at are mutually exclusive")
    if ttl is not None:
        duration_ms = _duration_ms(ttl, name="ttl")
        expiry = time.time_ns() // 1_000_000 + duration_ms
        if expiry > _MAX_EPOCH_MS:
            raise ConfigurationError("ttl is outside the supported range")
        return expiry
    if expires_at is None:
        return None
    if not isinstance(expires_at, datetime):
        raise TypeError("expires_at must be a datetime")
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise ConfigurationError("expires_at must be timezone-aware")
    try:
        milliseconds = math.ceil(expires_at.timestamp() * 1000)
    except (OverflowError, OSError, ValueError) as error:
        raise ConfigurationError("expires_at is outside the supported range") from error
    if milliseconds < 0 or milliseconds > _MAX_EPOCH_MS:
        raise ConfigurationError("expires_at is outside the supported range")
    return milliseconds


def _duration_ms(value: Seconds | timedelta, *, name: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be finite non-negative seconds or timedelta")
    seconds = value.total_seconds() if isinstance(value, timedelta) else value
    if not isinstance(seconds, (int, float)):
        raise TypeError(f"{name} must be finite non-negative seconds or timedelta")
    seconds_float = float(seconds)
    if not math.isfinite(seconds_float) or seconds_float < 0:
        raise ConfigurationError(f"{name} must be finite and non-negative")
    milliseconds = math.ceil(seconds_float * 1000)
    if milliseconds > _MAX_EPOCH_MS:
        raise ConfigurationError(f"{name} is outside the supported range")
    return milliseconds


def _positive_duration_ms(value: Seconds | timedelta, *, name: str) -> int:
    milliseconds = _duration_ms(value, name=name)
    if milliseconds == 0:
        raise ConfigurationError(f"{name} must be positive")
    return milliseconds


def _datetime_from_ms(value: int | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, tz=UTC)


def _value_kind(value: int) -> ValueKind:
    if value == _BYTES_KIND:
        return ValueKind.BYTES
    if value == _JSON_KIND:
        return ValueKind.JSON
    raise RuntimeError("native core returned an unknown value kind")


__all__ = ["FileBackend", "MasterKey", "RedisBackend", "TenantStore", "Vaultlet"]
