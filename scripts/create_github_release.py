"""Create the versioned GitHub release that triggers trusted PyPI publishing."""

from __future__ import annotations

import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

_DEFAULT_BRANCH = "main"
_PYPI_ENVIRONMENT = "pypi"
_REPOSITORY = "s-block/vaultlet"


@dataclass(frozen=True)
class Release:
    """A validated release tag pinned to one commit."""

    tag: str
    commit: str


def _executable(name: str) -> str:
    executable = which(name)
    if executable is None:
        raise RuntimeError(f"{name} is required to create a GitHub release")
    return executable


def _run(
    command: Sequence[str], *, cwd: Path, capture_output: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
    )


def _require_success(result: subprocess.CompletedProcess[str], message: str) -> None:
    if result.returncode == 0:
        return
    detail = (result.stderr or result.stdout or "").strip()
    suffix = f": {detail}" if detail else ""
    raise RuntimeError(f"{message}{suffix}")


def _output(command: Sequence[str], *, cwd: Path, message: str) -> str:
    result = _run(command, cwd=cwd)
    _require_success(result, message)
    return result.stdout.strip()


def _package_version(root: Path) -> str:
    data = tomllib.loads((root / "rust/Cargo.toml").read_text())
    package = data.get("package")
    if not isinstance(package, dict):
        raise RuntimeError("rust/Cargo.toml has no package table")
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise RuntimeError("rust/Cargo.toml has no package version")
    return version


def _prepare_release(root: Path, *, git: str, gh: str) -> Release:
    status = _output(
        [git, "status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        message="Could not inspect the worktree",
    )
    if status:
        raise RuntimeError("Refusing to release from a dirty worktree")

    branch = _output(
        [git, "branch", "--show-current"],
        cwd=root,
        message="Could not determine the current branch",
    )
    if branch != _DEFAULT_BRANCH:
        raise RuntimeError(f"Release from {_DEFAULT_BRANCH!r}, not {branch!r}")

    fetch = _run([git, "fetch", "origin", _DEFAULT_BRANCH, "--tags"], cwd=root)
    _require_success(fetch, "Could not refresh origin/main and release tags")

    commit = _output(
        [git, "rev-parse", "HEAD"],
        cwd=root,
        message="Could not resolve HEAD",
    )
    remote_commit = _output(
        [git, "rev-parse", f"origin/{_DEFAULT_BRANCH}"],
        cwd=root,
        message="Could not resolve origin/main",
    )
    if commit != remote_commit:
        raise RuntimeError("Local main must exactly match origin/main")

    auth = _run([gh, "auth", "status", "--hostname", "github.com"], cwd=root)
    _require_success(auth, "GitHub CLI authentication is required")

    environment = _run(
        [
            gh,
            "api",
            f"/repos/{_REPOSITORY}/environments/{_PYPI_ENVIRONMENT}",
        ],
        cwd=root,
    )
    if environment.returncode != 0:
        raise RuntimeError(
            "Create and protect the GitHub 'pypi' environment before releasing"
        )

    tag = f"v{_package_version(root)}"
    local_tag = _run(
        [git, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"], cwd=root
    )
    if local_tag.returncode == 0:
        raise RuntimeError(f"Tag {tag!r} already exists")

    release = _run([gh, "release", "view", tag, "--repo", _REPOSITORY], cwd=root)
    if release.returncode == 0:
        raise RuntimeError(f"GitHub release {tag!r} already exists")

    return Release(tag=tag, commit=commit)


def _publish_release(root: Path, *, gh: str, release: Release) -> None:
    result = _run(
        [
            gh,
            "release",
            "create",
            release.tag,
            "--repo",
            _REPOSITORY,
            "--target",
            release.commit,
            "--title",
            release.tag,
            "--generate-notes",
        ],
        cwd=root,
        capture_output=False,
    )
    _require_success(result, f"Could not create GitHub release {release.tag}")


def main() -> None:
    """Validate and publish the package version from the current main commit."""
    root = Path(__file__).resolve().parents[1]
    try:
        git = _executable("git")
        gh = _executable("gh")
        release = _prepare_release(root, git=git, gh=gh)
        print(f"Creating {release.tag} from {release.commit}")
        _publish_release(root, gh=gh, release=release)
        print("The Publish to PyPI workflow has been triggered on GitHub.")
    except RuntimeError as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
