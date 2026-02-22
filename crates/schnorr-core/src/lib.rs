pub mod curve;
pub mod hash;
pub mod keypair;
pub mod sign;
pub mod verify;

// Re-exports for convenience
pub use curve::{BjjPoint, BjjScalar};
pub use hash::{hash_message_to_field, schnorr_challenge};
pub use keypair::{KeyPair, PublicKey};
pub use sign::Signature;
pub use verify::{verify, VerifyResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let messages = [
            b"hello world".to_vec(),
            b"".to_vec(),
            b"schnorr over babyjubjub".to_vec(),
            vec![0xFF; 256],
        ];

        for msg in &messages {
            let sig = Signature::sign(&kp, msg);
            assert_eq!(
                verify(&sig, msg, &kp.pk),
                VerifyResult::Valid,
                "signature should verify for message {:?}",
                &msg[..msg.len().min(20)]
            );
        }
    }

    #[test]
    fn multiple_keypairs_independent() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let msg = b"shared message";

        let sig1 = Signature::sign(&kp1, msg);
        let sig2 = Signature::sign(&kp2, msg);

        // Each sig verifies with its own key
        assert_eq!(verify(&sig1, msg, &kp1.pk), VerifyResult::Valid);
        assert_eq!(verify(&sig2, msg, &kp2.pk), VerifyResult::Valid);

        // Cross-verification fails
        assert_eq!(verify(&sig1, msg, &kp2.pk), VerifyResult::Invalid);
        assert_eq!(verify(&sig2, msg, &kp1.pk), VerifyResult::Invalid);
    }

    #[test]
    fn deterministic_signing() {
        let kp = KeyPair::generate();
        let msg = b"deterministic test";

        let sig1 = Signature::sign(&kp, msg);
        let sig2 = Signature::sign(&kp, msg);

        assert_eq!(sig1.s, sig2.s, "same key+msg must give same s");
        assert_eq!(sig1.e, sig2.e, "same key+msg must give same e");
        assert_eq!(sig1.r, sig2.r, "same key+msg must give same R");
    }

    #[test]
    fn generator_compatibility_check() {
        // Verify that our generator produces coordinates matching circomlib's Base8
        let g = BjjPoint::generator();
        let (x, y) = g.coords();

        let expected_x = curve::bn254_to_dec_string(&x);
        let expected_y = curve::bn254_to_dec_string(&y);

        assert_eq!(expected_x, curve::BASE8_X);
        assert_eq!(expected_y, curve::BASE8_Y);
    }
}
