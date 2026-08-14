# Development

Vaultlet supports CPython 3.12 through 3.14 and Rust 1.89. The pinned Rust toolchain,
Maturin mixed-package build, uv lock, Ruff, strict mypy, pytest, Cargo format/Clippy/
tests, and pre-commit form the local toolchain.

## Set up the repository

Install [uv](https://docs.astral.sh/uv/) and
[rustup](https://rustup.rs/), then install the locked environment:

```bash
rustup show
uv sync --dev --frozen
uv run pre-commit install
```

Maturin builds the private native module while uv installs the package. The crate uses
`abi3-py312`, so one wheel per platform and architecture covers standard CPython
3.12-3.14.

## Run checks

```bash
make check
uv run pre-commit run --all-files
```

The full gate runs Rust formatting, Clippy with warnings denied, Rust tests, Python
format/lint/strict typing/tests, native sdist and wheel builds, metadata/content
validation, and an encrypted isolated-wheel round trip. Individual targets include:

```bash
make rust-format-check
make rust-lint
make rust-test
make format-check
make lint
make type-check
make test
make test-cov
make check-dist
```

Supply `PYO3_PYTHON` if Cargo cannot locate the uv interpreter for direct test or
Clippy commands. Security-policy checks used in CI are:

```bash
cargo audit --file rust/Cargo.lock
cargo deny --manifest-path rust/Cargo.toml check
```

Redis integration tests are opt-in locally. Start a disposable Redis 7.2 or newer
instance with AOF enabled, then set the endpoint before running the Python and Rust
contracts:

```bash
export VAULTLET_TEST_REDIS_ENDPOINT=redis://127.0.0.1:6379/0
uv run pytest -v tests/test_redis.py
cargo test --manifest-path rust/Cargo.toml --all-features \
  redis_backend_obeys_contract_and_reopens -- --ignored
```

Set `VAULTLET_TEST_REDIS_USERNAME` and `VAULTLET_TEST_REDIS_PASSWORD` when the test
server requires ACL authentication. CI runs both contracts against an isolated Redis
service.

## Release

Release tags use `v<version>` and must match the single package version in
`rust/Cargo.toml`; installed Python metadata exposes that version. The publish
workflow first runs the complete locked package gate against the exact release
commit, then builds native manylinux and musllinux x86-64/arm64, macOS, and Windows
wheels plus one source distribution. Musllinux wheels are installed and exercised in
Alpine; publishing uses only the protected PyPI OIDC environment. No PyPI token is
stored in the repository.

After the repository controls below are configured, release the version declared in
`rust/Cargo.toml` with:

```bash
make release
```

The target runs the complete package gate, requires a clean `main` checkout that
exactly matches `origin/main`, verifies GitHub CLI authentication and the protected
`pypi` environment, then creates a versioned GitHub release pinned to that commit.
Publishing and all platform builds run on GitHub; local PyPI credentials are not used.

Before enabling public releases, configure repository controls that cannot be stored
in this checkout:

- enable GitHub Private Vulnerability Reporting;
- protect `v*` tags and restrict release creation to maintainers;
- restrict the `pypi` environment to protected release tags and require approval;
- configure the PyPI Trusted Publisher for `.github/workflows/publish.yml` and the
  `pypi` environment; and
- prevent release administrators from bypassing those protections where the
  repository's GitHub plan supports it.
