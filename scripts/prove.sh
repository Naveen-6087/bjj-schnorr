#!/usr/bin/env bash
# scripts/prove.sh — Generate a Groth16 proof from a witness input JSON
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
CIRCUIT_NAME="schnorr"

INPUT_FILE="${1:-${BUILD_DIR}/input.json}"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file not found: $INPUT_FILE"
    echo "Usage: $0 [input.json]"
    echo ""
    echo "Generate input.json using the Rust witness builder:"
    echo "  cargo run -p schnorr-witness -- sign --message 'hello'"
    exit 1
fi

echo "=== Generating witness ==="
node "${BUILD_DIR}/${CIRCUIT_NAME}_js/generate_witness.js" \
    "${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
    "$INPUT_FILE" \
    "${BUILD_DIR}/witness.wtns"

echo "=== Generating Groth16 proof ==="
npx snarkjs groth16 prove \
    "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
    "${BUILD_DIR}/witness.wtns" \
    "${BUILD_DIR}/proof.json" \
    "${BUILD_DIR}/public.json"

echo "=== Proof generated ==="
echo "  Proof:   ${BUILD_DIR}/proof.json"
echo "  Public:  ${BUILD_DIR}/public.json"
