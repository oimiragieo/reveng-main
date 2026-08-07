#!/usr/bin/env bash
# Build sharkdp/hexyl (release) and install the ELF under test_samples/native/hexyl/build/.
# The ELF and hexyl.sha256 are gitignored (test_samples/native/*/build/); the research
# doc pins the expected digest. Does not claim analyze capability or native GA.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/external/hexyl-benchmark/hexyl"
OUT_DIR="${ROOT}/test_samples/native/hexyl/build"
OUT_BIN="${OUT_DIR}/hexyl"
SHA_FILE="${OUT_DIR}/hexyl.sha256"

if [[ ! -f "${SRC}/Cargo.toml" ]]; then
  echo "error: missing hexyl sources at ${SRC}/Cargo.toml" >&2
  echo "  clone sharkdp/hexyl (tag v0.17.0) into external/hexyl-benchmark/hexyl" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not on PATH — install Rust toolchain to build hexyl fixture" >&2
  exit 1
fi

version="$(
  awk '
    /^\[package\]/ { in_pkg=1; next }
    /^\[/ { in_pkg=0 }
    in_pkg && /^version[[:space:]]*=/ {
      gsub(/"/, "", $3); print $3; exit
    }
  ' "${SRC}/Cargo.toml"
)"
if [[ -z "${version}" ]]; then
  echo "error: could not read package.version from ${SRC}/Cargo.toml" >&2
  exit 1
fi
echo "building hexyl ${version} from ${SRC}"

(
  cd "${SRC}"
  cargo build --release --locked
)

built="${SRC}/target/release/hexyl"
if [[ ! -f "${built}" ]]; then
  echo "error: expected release binary missing: ${built}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
cp -f "${built}" "${OUT_BIN}"
chmod +x "${OUT_BIN}"

# Provenance file next to the ELF (relative path form for portability).
(
  cd "${OUT_DIR}"
  sha256sum hexyl > hexyl.sha256
)

digest="$(awk '{print $1; exit}' "${SHA_FILE}")"
echo "installed ${OUT_BIN}"
echo "sha256 ${digest}  (wrote ${SHA_FILE})"
echo "hexyl_fixture_version=${version}"
