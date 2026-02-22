#!/usr/bin/env bash
# scripts/e2e_test.sh — Full end-to-end test: Rust sign → Circom prove → verify
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
CIRCUIT_NAME="schnorr"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Schnorr-BabyJubJub End-to-End Test                 ║"
echo "║  Rust sign → Circom witness → Groth16 proof         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ──────────────────────────────────────────────────────────
# Step 1: Build Rust workspace
# ──────────────────────────────────────────────────────────
echo "=== Step 1: Building Rust workspace ==="
cd "$PROJECT_DIR"
CARGO_TARGET_DIR=/tmp/bjj-schnorr-target cargo build --release 2>&1
echo "  ✓ Rust build complete"
echo ""

# ──────────────────────────────────────────────────────────
# Step 2: Run Rust unit tests
# ──────────────────────────────────────────────────────────
echo "=== Step 2: Running Rust tests ==="
CARGO_TARGET_DIR=/tmp/bjj-schnorr-target cargo test 2>&1
echo "  ✓ All Rust tests passed"
echo ""

# ──────────────────────────────────────────────────────────
# Step 3: Generate witness JSON using Rust
# ──────────────────────────────────────────────────────────
echo "=== Step 3: Generating witness (Rust → JSON) ==="
CARGO_TARGET_DIR=/tmp/bjj-schnorr-target cargo run -p schnorr-witness --release -- \
    --message "hello world" \
    --output "${BUILD_DIR}/input.json" 2>&1
echo "  ✓ Witness written to ${BUILD_DIR}/input.json"
cat "${BUILD_DIR}/input.json"
echo ""

# ──────────────────────────────────────────────────────────
# Step 4: Check that circuit artifacts exist
# ──────────────────────────────────────────────────────────
echo "=== Step 4: Checking circuit artifacts ==="
for f in "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
         "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
         "${BUILD_DIR}/verification_key.json" \
         "${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm"; do
    if [ ! -f "$f" ]; then
        echo "  ✗ Missing: $f"
        echo "  → Run scripts/setup.sh first"
        exit 1
    fi
done
echo "  ✓ All circuit artifacts present"
echo ""

# ──────────────────────────────────────────────────────────
# Step 5: Generate witness (snarkjs)
# ──────────────────────────────────────────────────────────
echo "=== Step 5: Generating WASM witness ==="
node "${BUILD_DIR}/${CIRCUIT_NAME}_js/generate_witness.js" \
    "${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
    "${BUILD_DIR}/input.json" \
    "${BUILD_DIR}/witness.wtns"
echo "  ✓ Witness generated"
echo ""

# ──────────────────────────────────────────────────────────
# Step 6: Generate Groth16 proof
# ──────────────────────────────────────────────────────────
echo "=== Step 6: Generating Groth16 proof ==="
npx snarkjs groth16 prove \
    "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
    "${BUILD_DIR}/witness.wtns" \
    "${BUILD_DIR}/proof.json" \
    "${BUILD_DIR}/public.json"
echo "  ✓ Proof generated"
echo ""

# ──────────────────────────────────────────────────────────
# Step 7: Verify proof
# ──────────────────────────────────────────────────────────
echo "=== Step 7: Verifying Groth16 proof ==="
RESULT=$(npx snarkjs groth16 verify \
    "${BUILD_DIR}/verification_key.json" \
    "${BUILD_DIR}/public.json" \
    "${BUILD_DIR}/proof.json" 2>&1)
echo "$RESULT"

if echo "$RESULT" | grep -q "OK"; then
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  ✓ END-TO-END TEST PASSED                           ║"
    echo "║  Schnorr signature verified inside ZK proof!        ║"
    echo "╚══════════════════════════════════════════════════════╝"
else
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  ✗ END-TO-END TEST FAILED                           ║"
    echo "╚══════════════════════════════════════════════════════╝"
    exit 1
fi
