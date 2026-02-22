// Schnorr signature verification over BabyJubJub.
//
// Given signature (s, e), public key PK, and message m:
//   1. R' = s · G + e · PK
//   2. e' = Poseidon(R'.x, PK.x, PK.y, H(m))
//   3. Accept iff e' == e
//
// Note: `e` is the full Poseidon output in F_p (not reduced mod n).
// The scalar multiplication `e · PK` naturally reduces mod n because
// the group has order n.

use ark_bn254::Fr as Bn254Fr;

use crate::curve::BjjPoint;
use crate::hash::{hash_message_to_field, schnorr_challenge};
use crate::keypair::PublicKey;
use crate::sign::Signature;

/// Result of signature verification.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Valid,
    Invalid,
}

/// Verify a Schnorr signature against a public key and message.
pub fn verify(sig: &Signature, message: &[u8], pk: &PublicKey) -> VerifyResult {
    let g = BjjPoint::generator();

    // R' = s · G  +  e · PK
    let s_g = g.scalar_mul(&sig.s);
    let e_pk = pk.point.mul_by_bn254_scalar(&sig.e);
    let r_prime = s_g.add(&e_pk);

    // Recompute challenge from R'
    let (r_prime_x, _) = r_prime.coords();
    let (pk_x, pk_y) = pk.coords();
    let msg_hash = hash_message_to_field(message);

    let e_check: Bn254Fr = schnorr_challenge(&r_prime_x, &pk_x, &pk_y, &msg_hash);

    if e_check == sig.e {
        VerifyResult::Valid
    } else {
        VerifyResult::Invalid
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;

    #[test]
    fn valid_signature_verifies() {
        let kp = KeyPair::generate();
        let msg = b"hello world";
        let sig = Signature::sign(&kp, msg);
        assert_eq!(verify(&sig, msg, &kp.pk), VerifyResult::Valid);
    }

    #[test]
    fn wrong_message_fails() {
        let kp = KeyPair::generate();
        let sig = Signature::sign(&kp, b"hello");
        assert_eq!(verify(&sig, b"world", &kp.pk), VerifyResult::Invalid);
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let sig = Signature::sign(&kp1, b"msg");
        assert_eq!(verify(&sig, b"msg", &kp2.pk), VerifyResult::Invalid);
    }

    #[test]
    fn empty_message() {
        let kp = KeyPair::generate();
        let sig = Signature::sign(&kp, b"");
        assert_eq!(verify(&sig, b"", &kp.pk), VerifyResult::Valid);
    }

    #[test]
    fn long_message() {
        let kp = KeyPair::generate();
        let msg = vec![0xABu8; 10_000];
        let sig = Signature::sign(&kp, &msg);
        assert_eq!(verify(&sig, &msg, &kp.pk), VerifyResult::Valid);
    }
}
