"""Master-key contract tests."""

import base64
import pickle

import pytest

import vaultlet


def test_key_generation_export_and_import() -> None:
    """Generated keys round-trip only through explicit export methods."""
    key = vaultlet.MasterKey.generate()
    raw = key.export_bytes()
    encoded = key.export_base64()

    assert len(raw) == 32
    assert base64.b64decode(encoded) == raw
    assert vaultlet.MasterKey.from_bytes(raw).export_bytes() == raw
    assert vaultlet.MasterKey.from_base64(encoded).export_bytes() == raw
    assert repr(key) == "MasterKey(<redacted>)"
    assert encoded not in repr(key)


def test_key_rejects_invalid_input_and_pickle() -> None:
    """Invalid lengths and implicit serialization fail without exposing material."""
    with pytest.raises(TypeError):
        vaultlet.MasterKey()
    with pytest.raises(vaultlet.ConfigurationError, match="32 bytes"):
        vaultlet.MasterKey.from_bytes(b"short")
    with pytest.raises(vaultlet.ConfigurationError, match="base64"):
        vaultlet.MasterKey.from_base64("not base64")
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(vaultlet.MasterKey.generate())
