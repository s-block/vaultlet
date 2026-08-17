# Contributing to Vaultlet

Vaultlet welcomes focused bug reports, documentation improvements, benchmark work,
platform validation, integration examples, and implementation changes. Open issues
track work that is ready for discussion or contribution.

Report suspected vulnerabilities privately by following the
[security policy](SECURITY.md), not through a public issue or pull request.

## Ways to contribute

- [Report a bug](https://github.com/s-block/vaultlet/issues/new?template=bug_report.yml)
  with a minimal reproduction and complete runtime/backend details.
- [Propose a backend, benchmark, or integration](https://github.com/s-block/vaultlet/issues/new?template=proposal.yml)
  before substantial implementation work so its contract and evidence can be
  reviewed early.
- Improve documentation, platform validation, tests, or an existing issue from the
  [current roadmap](https://github.com/s-block/vaultlet/issues).
- Report security issues only through
  [GitHub Private Vulnerability Reporting](https://github.com/s-block/vaultlet/security/advisories/new).

## Choose an issue

Start with the [open issues](https://github.com/s-block/vaultlet/issues). Comment on
an issue before beginning substantial work so the approach and package contract can
be aligned early. Open a focused proposal first when a change would add a backend,
integration, dependency, public API, storage-format revision, or compatibility
commitment.

Bug reports should include a minimal reproduction, the Vaultlet and Python versions,
the operating system, the selected storage engine, and the expected and observed
behaviour. Redis reports should also include the Redis version, topology, and
persistence configuration without credentials or private endpoints.

## Set up the repository

Install [uv](https://docs.astral.sh/uv/) and
[rustup](https://rustup.rs/), then install the locked development environment:

```bash
rustup show
uv sync --dev --frozen
uv run pre-commit install
```

Vaultlet supports CPython 3.12 through 3.14 and uses the pinned Rust 1.89 toolchain.
See [Development](docs/Development.md) for Redis integration tests, release details,
and individual validation commands.

## Make a focused change

- Keep the public Python API fully typed and export public names explicitly through
  `vaultlet.__all__`.
- Keep the native `vaultlet._vaultlet` module private behind the Python facade.
- Add focused tests for behaviour changes and preserve backend contract coverage.
- Keep project-owned Rust free of unsafe code.
- Update the relevant user, security, architecture, storage-format, or benchmark
  documentation when a contract changes.
- Do not include secrets, private endpoints, production data, or sensitive values in
  tests, logs, benchmark artifacts, issues, or pull requests.

## Validate the change

Run the complete package gate and pre-commit checks before opening a pull request:

```bash
uv sync --dev --frozen
make check
uv run pre-commit run --all-files
```

`make check` covers Rust formatting, Clippy with warnings denied, Rust tests, Python
formatting, linting, strict typing, tests, distribution metadata and contents, and an
isolated installation of the built wheel.

## Report benchmarks

Follow [Benchmarks](docs/Benchmarks.md) when changing performance-sensitive code or
publishing results. Retain raw output and enough environment metadata to repeat the
run. Keep value sizes, durability settings, and transaction boundaries aligned, and
label comparisons that do not provide equivalent encryption or durability.
