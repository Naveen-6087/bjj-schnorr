#!/usr/bin/env bash
# scripts/setup.sh — Compile circuit + Groth16 trusted setup
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
CIRCUIT_NAME="schnorr"
PTAU_FILE="${BUILD_DIR}/pot14_final.ptau"

echo "=== Step 1: Compile Circom circuit ==="
mkdir -p "$BUILD_DIR"
circom "${PROJECT_DIR}/circuits/${CIRCUIT_NAME}.circom" \
    --r1cs \
    --wasm \
    --sym \
    -l "${PROJECT_DIR}/node_modules" \
    --output "$BUILD_DIR"

echo ""
echo "Circuit info:"
npx snarkjs r1cs info "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"

echo ""
echo "=== Step 2: Download Powers of Tau (Phase 1) ==="
# pot14 supports up to 2^14 = 16384 constraints (our circuit has ~7400)
if [ ! -f "$PTAU_FILE" ]; then
    echo "Downloading pot14_final.ptau..."
    curl -L "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau" \
        -o "$PTAU_FILE"
else
    echo "Powers of Tau file already exists."
fi

echo ""
echo "=== Step 3: Groth16 Phase 2 Setup ==="
npx snarkjs groth16 setup \
    "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
    "$PTAU_FILE" \
    "${BUILD_DIR}/${CIRCUIT_NAME}_0.zkey"

echo ""
echo "=== Step 4: Contribute entropy ==="
echo "schnorr-bjj-dev-entropy-$(date +%s%N)" | \
    npx snarkjs zkey contribute \
        "${BUILD_DIR}/${CIRCUIT_NAME}_0.zkey" \
        "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
        --name="Dev contributor" \
        -v

echo ""
echo "=== Step 5: Export verification key ==="
npx snarkjs zkey export verificationkey \
    "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
    "${BUILD_DIR}/verification_key.json"

echo ""
echo "=== Step 6: Generate Solidity verifier ==="
mkdir -p "${PROJECT_DIR}/contracts"
npx snarkjs zkey export solidityverifier \
    "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
    "${PROJECT_DIR}/contracts/SchnorrVerifier.sol"

# Clean up intermediate zkey
rm -f "${BUILD_DIR}/${CIRCUIT_NAME}_0.zkey"

echo ""
echo "=== Setup complete ==="
echo "Build artifacts in: ${BUILD_DIR}/"
echo "  - ${CIRCUIT_NAME}.r1cs"
echo "  - ${CIRCUIT_NAME}.zkey"
echo "  - verification_key.json"
echo "  - ${CIRCUIT_NAME}_js/ (WASM witness generator)"
echo "Solidity verifier: contracts/SchnorrVerifier.sol"
