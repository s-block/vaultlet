"""Async encrypted, persistent, multi-tenant key-value storage."""

from importlib.metadata import PackageNotFoundError, version

from . import _vaultlet
from ._api import FileBackend, MasterKey, RedisBackend, TenantStore, Vaultlet
from ._errors import (
    BackendError,
    ClosedError,
    ConfigurationError,
    IntegrityError,
    InvalidKeyError,
    SerializationError,
    StoreLockedError,
    TypeMismatchError,
    UnsupportedFormatError,
    VaultletError,
)
from ._types import (
    MAX_BATCH_ITEMS,
    MAX_BATCH_VALUE_BYTES,
    MAX_KEY_LIST_LIMIT,
    EntryMetadata,
    JsonArray,
    JsonInput,
    JsonObject,
    JsonValue,
    KeyListing,
    StorageEngine,
    ValueKind,
)

try:
    __version__ = version("vaultlet")
except PackageNotFoundError:
    __version__ = _vaultlet.__version__

__all__ = [
    "MAX_BATCH_ITEMS",
    "MAX_BATCH_VALUE_BYTES",
    "MAX_KEY_LIST_LIMIT",
    "BackendError",
    "ClosedError",
    "ConfigurationError",
    "EntryMetadata",
    "FileBackend",
    "IntegrityError",
    "InvalidKeyError",
    "JsonArray",
    "JsonInput",
    "JsonObject",
    "JsonValue",
    "KeyListing",
    "MasterKey",
    "RedisBackend",
    "SerializationError",
    "StorageEngine",
    "StoreLockedError",
    "TenantStore",
    "TypeMismatchError",
    "UnsupportedFormatError",
    "ValueKind",
    "Vaultlet",
    "VaultletError",
    "__version__",
]
