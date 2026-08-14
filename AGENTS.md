# vaultlet Project Guide

Keep this Python package typed, minimal, reusable, and easy to review.

## Architecture

- `src/vaultlet/` owns the installable package.
- `rust/src/` owns security, storage, expiry, async-service, and PyO3 behavior.
- `tests/` mirrors the package structure as modules are added.
- `scripts/` contains package and distribution validation tools.
- `benchmarks/` and `rust/benches/` contain non-gating performance workloads.
- Keep public exports explicit through `vaultlet.__all__`.
- Keep the native `vaultlet._vaultlet` module private behind the typed Python facade.

Add modules and dependencies only when they support a concrete package feature.
Keep application, service, persistence, and deployment concerns outside this
library unless the package contract explicitly requires them.

## Python And Packaging

- Support Python 3.12 through 3.14.
- Keep code fully typed and deterministic.
- Use `uv`, Maturin, PyO3, Ruff, strict mypy, pytest, Cargo, and committed
  public-registry locks.
- Keep project-owned Rust free of unsafe code and use the pinned Rust 1.89
  toolchain with Rustfmt and Clippy warnings denied.
- Build `abi3-py312` wheels for standard CPython 3.12 through 3.14.
- Pin GitHub Actions to full commit SHAs.
- Publish only through the protected OIDC workflow; never add a PyPI token.

## Validation

```bash
uv sync --dev --frozen
make check
uv run pre-commit run --all-files
```

`make check` validates formatting, linting, typing, tests, wheel/sdist metadata,
artifact contents, and an isolated installation of the built wheel.
