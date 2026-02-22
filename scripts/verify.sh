#!/usr/bin/env bash
# scripts/verify.sh — Verify a Groth16 proof
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"

echo "=== Verifying Groth16 proof ==="
npx snarkjs groth16 verify \
    "${BUILD_DIR}/verification_key.json" \
    "${BUILD_DIR}/public.json" \
    "${BUILD_DIR}/proof.json"
