"""GitHub release command tests."""

from __future__ import annotations

import subprocess
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Protocol, cast

import pytest

if TYPE_CHECKING:
    from collections.abc import Sequence


class _Release(Protocol):
    tag: str
    commit: str


class _ReleaseModule(Protocol):
    def _prepare_release(self, root: Path, *, git: str, gh: str) -> _Release: ...

    def _publish_release(self, root: Path, *, gh: str, release: _Release) -> None: ...


def _load_release_module() -> _ReleaseModule:
    path = Path(__file__).resolve().parents[1] / "scripts/create_github_release.py"
    spec = spec_from_file_location("vaultlet_create_github_release", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the GitHub release script")
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast("_ReleaseModule", module)


create_github_release = _load_release_module()


def _completed(
    command: Sequence[str], *, returncode: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


def test_release_is_pinned_to_clean_synchronized_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The release plan derives its tag and exact remote main commit."""
    rust = tmp_path / "rust"
    rust.mkdir()
    (rust / "Cargo.toml").write_text('[package]\nversion = "1.2.3"\n')
    commands: list[tuple[str, ...]] = []

    def fake_run(
        command: Sequence[str], *, cwd: Path, capture_output: bool = True
    ) -> subprocess.CompletedProcess[str]:
        del cwd, capture_output
        invocation = tuple(command)
        commands.append(invocation)
        outputs: dict[tuple[str, ...], str] = {
            ("git", "branch", "--show-current"): "main\n",
            ("git", "rev-parse", "HEAD"): "abc123\n",
            ("git", "rev-parse", "origin/main"): "abc123\n",
        }
        if invocation in {
            ("git", "rev-parse", "--verify", "--quiet", "refs/tags/v1.2.3"),
            ("gh", "release", "view", "v1.2.3", "--repo", "s-block/vaultlet"),
        }:
            return _completed(command, returncode=1)
        return _completed(command, stdout=outputs.get(invocation, ""))

    monkeypatch.setattr(create_github_release, "_run", fake_run)

    release = create_github_release._prepare_release(tmp_path, git="git", gh="gh")

    assert release.tag == "v1.2.3"
    assert release.commit == "abc123"
    assert (
        "gh",
        "api",
        "/repos/s-block/vaultlet/environments/pypi",
    ) in commands


def test_release_rejects_a_dirty_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local modification blocks release creation before any fetch or API call."""

    def fake_run(
        command: Sequence[str], *, cwd: Path, capture_output: bool = True
    ) -> subprocess.CompletedProcess[str]:
        del cwd, capture_output
        return _completed(command, stdout=" M README.md\n")

    monkeypatch.setattr(create_github_release, "_run", fake_run)

    with pytest.raises(RuntimeError, match="dirty worktree"):
        create_github_release._prepare_release(tmp_path, git="git", gh="gh")


def test_publish_uses_the_validated_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GitHub creates the release tag at the commit validated by preflight."""
    commands: list[tuple[str, ...]] = []

    def fake_run(
        command: Sequence[str], *, cwd: Path, capture_output: bool = True
    ) -> subprocess.CompletedProcess[str]:
        del cwd
        assert not capture_output
        commands.append(tuple(command))
        return _completed(command)

    monkeypatch.setattr(create_github_release, "_run", fake_run)

    create_github_release._publish_release(
        tmp_path,
        gh="gh",
        release=SimpleNamespace(tag="v1.2.3", commit="abc123"),
    )

    assert commands == [
        (
            "gh",
            "release",
            "create",
            "v1.2.3",
            "--repo",
            "s-block/vaultlet",
            "--target",
            "abc123",
            "--title",
            "v1.2.3",
            "--generate-notes",
        )
    ]
