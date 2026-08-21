# Codex cloud environment

Create the Codex cloud environment for `s-block/vaultlet` with the default
`universal` image and these settings:

- Python: `3.12`
- Setup script: `bash .codex/setup.sh`
- Maintenance script: `bash .codex/setup.sh`
- Environment variables and secrets: none required for validation

Rust is pinned by `rust-toolchain.toml`; the setup script installs that
toolchain with Clippy and Rustfmt, fetches the locked Cargo graph, builds the
Python development environment, and prepares pre-commit while setup-phase
internet access is available. Normal checks can keep agent internet access
disabled.

See the [Codex cloud environment documentation](https://developers.openai.com/codex/cloud/environments)
for the environment lifecycle and cache behavior.
