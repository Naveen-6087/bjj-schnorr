// Key generation for Schnorr signatures over BabyJubJub.
//
// Private key: random scalar sk ∈ Z_n  (BJJ subgroup order)
// Public key:  PK = sk · G  (a BabyJubJub curve point)

use crate::curve::{BjjPoint, BjjScalar};

/// A Schnorr keypair over BabyJubJub.
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// Secret scalar sk ∈ Z_n.
    pub sk: BjjScalar,
    /// Public key PK = sk · G.
    pub pk: PublicKey,
}

/// A Schnorr public key (a point on BabyJubJub).
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub point: BjjPoint,
}

impl KeyPair {
    /// Generate a fresh keypair using OS-seeded randomness.
    pub fn generate() -> Self {
        let mut rng = ark_std::rand::rngs::OsRng;
        let sk = BjjScalar::random(&mut rng);
        Self::from_private_key(sk)
    }

    /// Derive a keypair from an existing private scalar.
    pub fn from_private_key(sk: BjjScalar) -> Self {
        let g = BjjPoint::generator();
        let pk_point = g.scalar_mul(&sk);
        KeyPair {
            sk,
            pk: PublicKey { point: pk_point },
        }
    }
}

impl PublicKey {
    /// Get the (x, y) coordinates as BN254 field elements.
    pub fn coords(&self) -> (ark_bn254::Fr, ark_bn254::Fr) {
        self.point.coords()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair() {
        let kp = KeyPair::generate();
        assert!(!kp.pk.point.is_zero(), "public key must not be identity");
    }

    #[test]
    fn deterministic_from_private_key() {
        use ark_ed_on_bn254::Fr as BjjFr;
        let sk = BjjScalar(BjjFr::from(12345u64));
        let kp1 = KeyPair::from_private_key(sk.clone());
        let kp2 = KeyPair::from_private_key(sk);
        assert_eq!(kp1.pk.point, kp2.pk.point);
    }

    #[test]
    fn different_keys_different_pubkeys() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        // Overwhelmingly likely to differ
        assert_ne!(kp1.pk.point, kp2.pk.point);
    }
}
