// crates/schnorr-core/src/hash.rs
//
// Poseidon hash for Schnorr challenge computation.
//
// Uses `light-poseidon` which is specifically designed to produce the same
// output as circomlib's `Poseidon(n)` circuit over the BN254 scalar field.
//
// The Schnorr challenge is:
//   e = Poseidon(R.x, PK.x, PK.y, msgHash)
//
// Message-to-field conversion uses SHA-256 → reduce mod p.

use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};

/// Compute the Schnorr challenge hash:
///
///   e = Poseidon(r_x, pk_x, pk_y, message_hash)
///
/// All inputs and the output are elements of the BN254 scalar field F_p.
/// This is directly compatible with circomlib's `Poseidon(4)`.
pub fn schnorr_challenge(
    r_x: &Bn254Fr,
    pk_x: &Bn254Fr,
    pk_y: &Bn254Fr,
    message_hash: &Bn254Fr,
) -> Bn254Fr {
    let mut hasher =
        Poseidon::<Bn254Fr>::new_circom(4).expect("Poseidon initialization failed for width 4");

    hasher
        .hash(&[*r_x, *pk_x, *pk_y, *message_hash])
        .expect("Poseidon hash failed")
}

/// Hash an arbitrary byte-string message to a BN254 field element.
///
/// Method: SHA-256(message) → interpret as little-endian integer → reduce mod p.
///
/// This gives a deterministic, collision-resistant mapping from arbitrary
/// messages to field elements suitable for use as `msgHash` in the circuit.
pub fn hash_message_to_field(message: &[u8]) -> Bn254Fr {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(message);
    Bn254Fr::from_le_bytes_mod_order(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;

    #[test]
    fn poseidon_deterministic() {
        let a = Bn254Fr::one();
        let b = Bn254Fr::from(2u64);
        let c = Bn254Fr::from(3u64);
        let d = Bn254Fr::from(4u64);

        let h1 = schnorr_challenge(&a, &b, &c, &d);
        let h2 = schnorr_challenge(&a, &b, &c, &d);
        assert_eq!(h1, h2, "Poseidon must be deterministic");
    }

    #[test]
    fn poseidon_different_inputs_differ() {
        let a = Bn254Fr::one();
        let b = Bn254Fr::from(2u64);
        let c = Bn254Fr::from(3u64);

        let h1 = schnorr_challenge(&a, &b, &c, &a);
        let h2 = schnorr_challenge(&a, &b, &c, &b);
        assert_ne!(h1, h2, "different inputs should produce different hashes");
    }

    #[test]
    fn message_hash_deterministic() {
        let h1 = hash_message_to_field(b"hello world");
        let h2 = hash_message_to_field(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn message_hash_different_messages_differ() {
        let h1 = hash_message_to_field(b"hello");
        let h2 = hash_message_to_field(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn message_hash_nonzero() {
        let h = hash_message_to_field(b"test message");
        assert_ne!(h, Bn254Fr::from(0u64));
    }
}
