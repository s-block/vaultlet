"""Public value and metadata types."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from . import _vaultlet

if TYPE_CHECKING:
    from datetime import datetime


class JsonObject(Mapping[str, "JsonValue"]):
    """Immutable, lazily materialized JSON object returned by Vaultlet."""

    __slots__ = ()

    def to_builtin(self) -> dict[str, JsonInput]:
        """Materialize this view as mutable built-in containers."""
        raise NotImplementedError


class JsonArray(Sequence["JsonValue"]):
    """Immutable, lazily materialized JSON array returned by Vaultlet."""

    __slots__ = ()

    def to_builtin(self) -> list[JsonInput]:
        """Materialize this view as mutable built-in containers."""
        raise NotImplementedError


type JsonValue = bool | int | float | str | JsonArray | JsonObject | None
type JsonInput = (
    bool
    | int
    | float
    | str
    | list["JsonInput"]
    | dict[str, "JsonInput"]
    | JsonArray
    | JsonObject
    | None
)

JsonObject.register(_vaultlet._JsonObject)
JsonArray.register(_vaultlet._JsonArray)

MAX_BATCH_ITEMS: Final = _vaultlet.MAX_BATCH_ITEMS
MAX_BATCH_VALUE_BYTES: Final = _vaultlet.MAX_BATCH_VALUE_BYTES
MAX_KEY_LIST_LIMIT: Final = _vaultlet.MAX_KEY_LIST_LIMIT


class ValueKind(StrEnum):
    """Encoding used for a stored value."""

    BYTES = "bytes"
    JSON = "json"


class StorageEngine(StrEnum):
    """Native file engine used by a Vaultlet store."""

    SQLITE = "sqlite"
    REDB = "redb"


@dataclass(frozen=True, slots=True)
class EntryMetadata:
    """Authenticated metadata for one live entry."""

    kind: ValueKind
    encoded_size: int
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class KeyListing:
    """One bounded key-listing page and its optional continuation cursor.

    Expired entries are omitted after authentication. ``has_more`` reflects an
    encrypted lookahead row, so it can be true when ``keys`` contains fewer entries
    than the requested limit. Pass ``next_cursor`` to the next ``keys`` call to
    continue scanning the tenant catalogue.
    """

    keys: tuple[str, ...]
    has_more: bool
    next_cursor: str | None = None


type Seconds = int | float

__all__ = [
    "MAX_BATCH_ITEMS",
    "MAX_BATCH_VALUE_BYTES",
    "MAX_KEY_LIST_LIMIT",
    "EntryMetadata",
    "JsonArray",
    "JsonInput",
    "JsonObject",
    "JsonValue",
    "KeyListing",
    "StorageEngine",
    "ValueKind",
]
