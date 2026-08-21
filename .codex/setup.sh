#!/usr/bin/env bash
set -euo pipefail

required_uv_version="0.10.4"
installed_uv_version="$(uv --version 2>/dev/null || true)"
if [[ "${installed_uv_version}" != "uv ${required_uv_version}"* ]]; then
    curl -LsSf "https://astral.sh/uv/${required_uv_version}/install.sh" | sh
    export PATH="${HOME}/.local/bin:${PATH}"
    hash -r
fi

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
uv run --frozen pre-commit install-hooks
