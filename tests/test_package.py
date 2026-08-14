"""Package metadata and public surface tests."""

import subprocess
import sys
from pathlib import Path

import vaultlet
from vaultlet import _vaultlet


def test_package_version_and_exports() -> None:
    """The package exposes one intentional, typed public API."""
    assert vaultlet.__version__ == "0.1.0"
    assert _vaultlet.__version__ == vaultlet.__version__
    assert set(vaultlet.__all__) == {
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
        "MAX_BATCH_ITEMS",
        "MAX_BATCH_VALUE_BYTES",
        "MAX_KEY_LIST_LIMIT",
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
    }


def test_error_hierarchy() -> None:
    """All operational errors share a stable root."""
    for error in (
        vaultlet.BackendError,
        vaultlet.ClosedError,
        vaultlet.ConfigurationError,
        vaultlet.IntegrityError,
        vaultlet.InvalidKeyError,
        vaultlet.SerializationError,
        vaultlet.StoreLockedError,
        vaultlet.TypeMismatchError,
    ):
        assert issubclass(error, vaultlet.VaultletError)
    assert issubclass(vaultlet.UnsupportedFormatError, vaultlet.IntegrityError)


def test_release_workflows_build_and_install_both_musllinux_architectures() -> None:
    """CI and release automation exercise installable musllinux wheels."""
    root = Path(__file__).resolve().parents[1]
    publish = (root / ".github/workflows/publish.yml").read_text()
    ci = (root / ".github/workflows/ci.yml").read_text()
    for workflow in (publish, ci):
        assert "x86_64-unknown-linux-musl" in workflow
        assert "aarch64-unknown-linux-musl" in workflow
        assert "manylinux: musllinux_1_2" in workflow
        assert "python:3.12-alpine" in workflow
        assert "scripts/release_smoke.py" in workflow


def test_publish_workflow_gates_and_uses_locked_validation_tools() -> None:
    """Publishing validates the exact commit without release dependency caches."""
    root = Path(__file__).resolve().parents[1]
    publish = (root / ".github/workflows/publish.yml").read_text()
    assert "name: Verify release commit" in publish
    assert "run: make check" in publish
    assert "uv run --no-sync twine check dist/*" in publish
    assert "uvx " not in publish
    assert "enable-cache: true" not in publish
    assert "sccache: true" not in publish


def test_security_policy_has_a_private_reporting_route() -> None:
    """The public repository directs vulnerability reports away from issues."""
    root = Path(__file__).resolve().parents[1]
    policy = (root / "SECURITY.md").read_text()
    assert "Private Vulnerability Reporting" in policy
    assert "Do not disclose" in policy


def test_examples_are_disposable_and_rerunnable(tmp_path: Path) -> None:
    """Examples do not strand persistent data behind a discarded generated key."""
    root = Path(__file__).resolve().parents[1]
    for name in ("agent_checkpoint.py", "credentials_ttl.py", "multi_tenant.py"):
        example = root / "examples" / name
        for _ in range(2):
            subprocess.run(  # noqa: S603 - interpreter and example are controlled
                [sys.executable, str(example)], cwd=tmp_path, check=True
            )
