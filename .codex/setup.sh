#!/usr/bin/env bash
set -euo pipefail

uv python install 3.12
rustup toolchain install 1.89.0 --profile minimal \
    --component clippy \
    --component rustfmt
rust_toolchain_bin="$(dirname "$(rustup which --toolchain 1.89.0 cargo)")"
export PATH="${rust_toolchain_bin}:${PATH}"
rust_profile="export PATH=\"${rust_toolchain_bin}:\$PATH\""
touch "${HOME}/.bashrc"
if ! grep -Fqx "${rust_profile}" "${HOME}/.bashrc"; then
    printf '\n%s\n' "${rust_profile}" >>"${HOME}/.bashrc"
fi
cargo fetch --manifest-path rust/Cargo.toml --locked
uv sync --python 3.12 --dev --frozen
uv run pre-commit install-hooks
