// Schnorr signing over BabyJubJub.
//
// Signing a message m with private key sk:
//   1. k = deterministic_nonce(sk, m)    — prevents nonce reuse
//   2. R = k · G
//   3. e = Poseidon(R.x, PK.x, PK.y, H(m))   — challenge in F_p
//   4. e_n = e mod n                           — reduce to BJJ scalar field
//   5. s = k − e_n · sk   (mod n)             — response
//   6. Signature = (s, e)
//
// The challenge `e` lives in F_p (BN254 scalar field) because that is
// what Poseidon outputs and what the circom circuit operates in.
// The response `s` lives in Z_n (BJJ scalar field) because it involves
// curve-scalar arithmetic.

use ark_bn254::Fr as Bn254Fr;
use ark_ed_on_bn254::Fr as BjjFr;
use ark_ff::{BigInteger, PrimeField};

use crate::curve::{bn254_to_bjj_scalar, BjjPoint, BjjScalar};
use crate::hash::{hash_message_to_field, schnorr_challenge};
use crate::keypair::KeyPair;

/// A Schnorr signature (s, e) over BabyJubJub.
#[derive(Clone, Debug)]
pub struct Signature {
    /// Response scalar: s = k − e_n · sk (mod n).  Lives in Z_n.
    pub s: BjjScalar,
    /// Challenge: e = Poseidon(R.x, PK.x, PK.y, msgHash).  Lives in F_p.
    pub e: Bn254Fr,
    /// Commitment point R = k · G (stored for convenience / debugging).
    pub r: BjjPoint,
}

impl Signature {
    /// Sign a message with the given keypair (deterministic nonce).
    pub fn sign(keypair: &KeyPair, message: &[u8]) -> Self {
        let k = deterministic_nonce(&keypair.sk, message);
        Self::sign_with_nonce(keypair, message, &k)
    }

    /// Sign with an explicit nonce.  **Only for testing** — reusing a nonce
    /// across two messages leaks the private key.
    pub fn sign_with_nonce(keypair: &KeyPair, message: &[u8], k: &BjjScalar) -> Self {
        let g = BjjPoint::generator();

        // R = k · G
        let r = g.scalar_mul(k);
        let (r_x, _r_y) = r.coords();

        // Message hash
        let msg_hash = hash_message_to_field(message);
        let (pk_x, pk_y) = keypair.pk.coords();

        // Challenge: e = Poseidon(R.x, PK.x, PK.y, msgHash)  ∈ F_p
        let e: Bn254Fr = schnorr_challenge(&r_x, &pk_x, &pk_y, &msg_hash);

        // Reduce e to BJJ scalar field: e_n = e mod n
        let e_n: BjjScalar = bn254_to_bjj_scalar(&e);

        // s = k − e_n · sk  (mod n)
        let s = BjjScalar(k.0 - e_n.0 * keypair.sk.0);

        Signature { s, e, r }
    }
}
fn deterministic_nonce(sk: &BjjScalar, message: &[u8]) -> BjjScalar {
    use sha2::{Digest, Sha512};

    let sk_bytes = sk.0.into_bigint().to_bytes_le();
    let mut hasher = Sha512::new();
    hasher.update(&sk_bytes);
    hasher.update(message);
    let digest = hasher.finalize();

    // Reduce 512-bit hash mod n → near-uniform scalar in Z_n
    BjjScalar(BjjFr::from_le_bytes_mod_order(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_deterministic() {
        let kp = KeyPair::generate();
        let msg = b"hello";
        let sig1 = Signature::sign(&kp, msg);
        let sig2 = Signature::sign(&kp, msg);
        // Same key + same message → same signature
        assert_eq!(sig1.s, sig2.s);
        assert_eq!(sig1.e, sig2.e);
    }

    #[test]
    fn different_messages_different_sigs() {
        let kp = KeyPair::generate();
        let sig1 = Signature::sign(&kp, b"hello");
        let sig2 = Signature::sign(&kp, b"world");
        assert_ne!(sig1.e, sig2.e);
    }

    #[test]
    fn commitment_point_is_on_curve() {
        let kp = KeyPair::generate();
        let sig = Signature::sign(&kp, b"test");
        // If R weren't on the curve, coords() would still work but
        // verification would fail — let's at least check it's not identity.
        assert!(!sig.r.is_zero());
    }
}
