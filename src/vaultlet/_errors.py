"""Stable public exceptions raised by Vaultlet."""

from ._vaultlet import (
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

__all__ = [
    "BackendError",
    "ClosedError",
    "ConfigurationError",
    "IntegrityError",
    "InvalidKeyError",
    "SerializationError",
    "StoreLockedError",
    "TypeMismatchError",
    "UnsupportedFormatError",
    "VaultletError",
]
