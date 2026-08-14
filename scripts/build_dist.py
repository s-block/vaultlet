"""Build distributions, including in repositories without an initial commit."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from shutil import which


def _executable(name: str) -> str:
    executable = which(name)
    if executable is None:
        raise RuntimeError(f"{name} is required to build distributions")
    return executable


def _has_head() -> bool:
    result = subprocess.run(
        [_executable("git"), "rev-parse", "--verify", "HEAD"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _ignore(_: str, names: list[str]) -> set[str]:
    ignored = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "dist",
        "prompts",
        "target",
    }
    return ignored.intersection(names)


def _run_build(root: Path) -> None:
    subprocess.run(
        [_executable("uv"), "build"],
        cwd=root,
        check=True,
    )


def main() -> None:
    """Build in place, or from a VCS-free copy before the first commit exists."""
    root = Path(__file__).resolve().parents[1]
    dist = root / "dist"
    shutil.rmtree(dist, ignore_errors=True)
    if _has_head():
        _run_build(root)
        return

    with tempfile.TemporaryDirectory(prefix="vaultlet-build-") as directory:
        source = Path(directory) / "source"
        shutil.copytree(root, source, ignore=_ignore)
        _run_build(source)
        shutil.copytree(source / "dist", dist)


if __name__ == "__main__":
    main()
