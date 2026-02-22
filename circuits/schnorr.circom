pragma circom 2.1.6;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";

/*
 * SchnorrVerify
 *
 * Proves knowledge of a valid Schnorr signature (s, e) over BabyJubJub
 * for a given public key and message hash, without revealing (s, e).
 *
 * Verification equation:
 *   R' = s·G + e·PK
 *   e  == Poseidon(R'.x, pkX, pkY, msgHash)
 *
 * The circuit uses a single Poseidon hash (not two) — the prover provides
 * (s, e) directly, and the circuit verifies consistency.
 *
 * Public inputs:  pkX, pkY, msgHash
 * Private inputs: s, e
 */
template SchnorrVerify() {

    signal input pkX;           // Public key X coordinate
    signal input pkY;           // Public key Y coordinate
    signal input msgHash;       // H(message), a BN254 field element

    signal input s;             // Response scalar (integer < n ≈ 2^251)
    signal input e;             // Challenge (Poseidon output, < p ≈ 2^254)

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component pkCheck = BabyCheck();
    pkCheck.x <== pkX;
    pkCheck.y <== pkY;

    component sBits = Num2Bits(253);
    sBits.in <== s;

    component eBits = Num2Bits(254);
    eBits.in <== e;

    component sG = EscalarMulFix(253, BASE8);
    for (var i = 0; i < 253; i++) {
        sG.e[i] <== sBits.out[i];
    }

    component ePK = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        ePK.e[i] <== eBits.out[i];
    }
    ePK.p[0] <== pkX;
    ePK.p[1] <== pkY;

    component adder = BabyAdd();
    adder.x1 <== sG.out[0];
    adder.y1 <== sG.out[1];
    adder.x2 <== ePK.out[0];
    adder.y2 <== ePK.out[1];

    component hasher = Poseidon(4);
    hasher.inputs[0] <== adder.xout;    // R'.x
    hasher.inputs[1] <== pkX;
    hasher.inputs[2] <== pkY;
    hasher.inputs[3] <== msgHash;
    hasher.out === e;
}

component main {public [pkX, pkY, msgHash]} = SchnorrVerify();
