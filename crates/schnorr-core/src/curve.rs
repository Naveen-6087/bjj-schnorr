// crates/schnorr-core/src/curve.rs
//
// BabyJubJub curve arithmetic with circomlib-compatible coordinates.
//
// We implement twisted Edwards curve operations directly over ark_bn254::Fr
// to match circomlib's coordinate system exactly. This avoids the mismatch
// between arkworks' (a=1) parameterization and circomlib's (a=168700).
//
// Curve equation:  a*x^2 + y^2 = 1 + d*x^2*y^2
//   a = 168700
//   d = 168696
//   Fq = F_p where p = BN254 scalar field prime
//
// Identity point: (0, 1)
// Generator (Base8): from circomlib
// Subgroup order: n ~ 2^251

use ark_bn254::Fr as Fq; // base field of BJJ = scalar field of BN254
use ark_ed_on_bn254::Fr; // scalar field of BJJ (subgroup order n)
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::UniformRand;
use num_bigint::BigUint;

pub const A_COEFF: u64 = 168700;

pub const D_COEFF: u64 = 168696;

pub const BASE8_X: &str = "5299619240641551281634865583518297030282874472190772894086521144482721001553";


pub const BASE8_Y: &str = "16950150798460657717958625567821834550301663161624707787222815936182638968203";

/// BabyJubJub subgroup order n (decimal)
pub const BJJ_ORDER: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";

pub fn field_from_dec_str<F: PrimeField>(s: &str) -> F {
    let biguint: BigUint = s.parse().expect("invalid decimal string");
    let bytes = biguint.to_bytes_le();
    F::from_le_bytes_mod_order(&bytes)
}

/// A point on the BabyJubJub twisted Edwards curve.
/// Stored as affine (x, y) in the BN254 scalar field. The identity is (0, 1).
#[derive(Clone, Debug)]
pub struct BjjPoint {
    pub x: Fq,
    pub y: Fq,
}

impl BjjPoint {
    /// The identity point (0, 1).
    pub fn identity() -> Self {
        BjjPoint {
            x: Fq::from(0u64),
            y: Fq::from(1u64),
        }
    }

    /// The circomlib Base8 generator of the prime-order subgroup.
    pub fn generator() -> Self {
        BjjPoint {
            x: field_from_dec_str(BASE8_X),
            y: field_from_dec_str(BASE8_Y),
        }
    }

    /// Check if this point lies on the curve: a*x^2 + y^2 = 1 + d*x^2*y^2
    pub fn is_on_curve(&self) -> bool {
        let a = Fq::from(A_COEFF);
        let d = Fq::from(D_COEFF);
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        let lhs = a * x2 + y2;
        let rhs = Fq::from(1u64) + d * x2 * y2;
        lhs == rhs
    }

    /// Check if this is the identity point (0, 1).
    pub fn is_zero(&self) -> bool {
        self.x == Fq::from(0u64) && self.y == Fq::from(1u64)
    }

    /// Twisted Edwards point addition.
    ///
    /// (x1,y1) + (x2,y2) = (x3,y3) where:
    ///   x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
    ///   y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
    pub fn add(&self, other: &BjjPoint) -> BjjPoint {
        let a = Fq::from(A_COEFF);
        let d = Fq::from(D_COEFF);

        let x1y2 = self.x * other.y;
        let y1x2 = self.y * other.x;
        let x1x2 = self.x * other.x;
        let y1y2 = self.y * other.y;

        let dx1x2y1y2 = d * x1x2 * y1y2;

        let one = Fq::from(1u64);

        // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
        let x3_num = x1y2 + y1x2;
        let x3_den = one + dx1x2y1y2;
        let x3 = x3_num * x3_den.inverse().expect("degenerate addition");

        // y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
        let y3_num = y1y2 - a * x1x2;
        let y3_den = one - dx1x2y1y2;
        let y3 = y3_num * y3_den.inverse().expect("degenerate addition");

        BjjPoint { x: x3, y: y3 }
    }

    /// Scalar multiplication by a BJJ scalar (double-and-add).
    pub fn scalar_mul(&self, scalar: &BjjScalar) -> BjjPoint {
        let bits = scalar.to_bits_le();
        let mut result = BjjPoint::identity();
        let mut temp = self.clone();

        for bit in bits {
            if bit {
                result = result.add(&temp);
            }
            temp = temp.add(&temp); // double
        }

        result
    }

    /// Scalar multiplication by a BN254 field element.
    ///
    /// Used for computing e * PK where e is a Poseidon hash output.
    /// The group has order n, so this naturally computes (e mod n) * PK.
    pub fn mul_by_bn254_scalar(&self, scalar: &Fq) -> BjjPoint {
        let bits = bn254_to_bits_le(scalar);
        let mut result = BjjPoint::identity();
        let mut temp = self.clone();

        for bit in bits {
            if bit {
                result = result.add(&temp);
            }
            temp = temp.add(&temp);
        }

        result
    }

    /// Get (x, y) coordinates. Already in BN254 scalar field.
    pub fn coords(&self) -> (Fq, Fq) {
        (self.x, self.y)
    }
}

impl PartialEq for BjjPoint {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x && self.y == other.y
    }
}

impl Eq for BjjPoint {}

/// A scalar in the BabyJubJub subgroup field Z_n.
#[derive(Clone, Debug)]
pub struct BjjScalar(pub Fr);

impl BjjScalar {
    /// Sample a uniformly random scalar.
    pub fn random<R: ark_std::rand::RngCore>(rng: &mut R) -> Self {
        Self(Fr::rand(rng))
    }

    /// Zero scalar.
    pub fn zero() -> Self {
        Self(Fr::from(0u64))
    }

    /// Convert to little-endian byte representation.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.into_bigint().to_bytes_le()
    }

    /// Convert to a decimal string (for JSON / witness export).
    pub fn to_dec_string(&self) -> String {
        let bytes = self.0.into_bigint().to_bytes_le();
        BigUint::from_bytes_le(&bytes).to_string()
    }

    /// Get bits in little-endian order (for scalar multiplication).
    pub fn to_bits_le(&self) -> Vec<bool> {
        let bigint = self.0.into_bigint();
        let bytes = bigint.to_bytes_le();
        let mut bits = Vec::with_capacity(256);
        for byte in &bytes {
            for i in 0..8u32 {
                bits.push((byte >> i) & 1 == 1);
            }
        }
        // Trim to 253 bits (BJJ scalar field size ~ 2^251)
        bits.truncate(253);
        bits
    }
}

impl PartialEq for BjjScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for BjjScalar {}
/// Convert a BN254 Fr element to a BJJ scalar (mod n).
pub fn bn254_to_bjj_scalar(e: &Fq) -> BjjScalar {
    let bytes = e.into_bigint().to_bytes_le();
    BjjScalar(Fr::from_le_bytes_mod_order(&bytes))
}

/// Convert a BN254 Fr element to a decimal string.
pub fn bn254_to_dec_string(f: &Fq) -> String {
    let bytes = f.into_bigint().to_bytes_le();
    BigUint::from_bytes_le(&bytes).to_string()
}

/// Get little-endian bits of a BN254 field element.
fn bn254_to_bits_le(f: &Fq) -> Vec<bool> {
    let bigint = f.into_bigint();
    let bytes = bigint.to_bytes_le();
    let mut bits = Vec::with_capacity(256);
    for byte in &bytes {
        for i in 0..8u32 {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits.truncate(254);
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_on_curve() {
        let g = BjjPoint::generator();
        assert!(g.is_on_curve(), "Base8 generator must be on curve");
    }

    #[test]
    fn identity_is_on_curve() {
        let id = BjjPoint::identity();
        assert!(id.is_on_curve(), "identity must be on curve");
    }

    #[test]
    fn generator_is_not_identity() {
        let g = BjjPoint::generator();
        assert!(!g.is_zero());
    }

    #[test]
    fn add_identity() {
        let g = BjjPoint::generator();
        let id = BjjPoint::identity();
        let result = g.add(&id);
        assert_eq!(result, g, "G + 0 = G");
    }

    #[test]
    fn scalar_mul_by_one() {
        let g = BjjPoint::generator();
        let one = BjjScalar(Fr::from(1u64));
        let result = g.scalar_mul(&one);
        assert!(result.is_on_curve());
        assert_eq!(g, result, "1*G = G");
    }

    #[test]
    fn scalar_mul_by_zero() {
        let g = BjjPoint::generator();
        let zero = BjjScalar::zero();
        let result = g.scalar_mul(&zero);
        assert!(result.is_zero(), "0*G = identity");
    }

    #[test]
    fn scalar_mul_associative() {
        let g = BjjPoint::generator();
        let a = BjjScalar(Fr::from(7u64));
        let b = BjjScalar(Fr::from(13u64));

        let ag = g.scalar_mul(&a);
        let bg = g.scalar_mul(&b);
        let sum_points = ag.add(&bg);

        let ab = BjjScalar(a.0 + b.0);
        let sum_scalar = g.scalar_mul(&ab);

        assert!(sum_points.is_on_curve());
        assert_eq!(sum_points, sum_scalar);
    }

    #[test]
    fn double_equals_add_self() {
        let g = BjjPoint::generator();
        let doubled = g.add(&g);
        let two = BjjScalar(Fr::from(2u64));
        let scaled = g.scalar_mul(&two);
        assert_eq!(doubled, scaled);
    }

    #[test]
    fn bn254_scalar_mul_matches() {
        let g = BjjPoint::generator();
        let val_bn254 = Fq::from(42u64);
        let result_bn254 = g.mul_by_bn254_scalar(&val_bn254);

        let val_bjj = bn254_to_bjj_scalar(&val_bn254);
        let result_bjj = g.scalar_mul(&val_bjj);

        assert_eq!(result_bn254, result_bjj);
    }

    #[test]
    fn generator_coordinates_match_circomlib() {
        let g = BjjPoint::generator();
        let (x, y) = g.coords();
        assert_eq!(bn254_to_dec_string(&x), BASE8_X);
        assert_eq!(bn254_to_dec_string(&y), BASE8_Y);
    }

    #[test]
    fn scalar_mul_result_on_curve() {
        let g = BjjPoint::generator();
        let s = BjjScalar(Fr::from(123456789u64));
        let p = g.scalar_mul(&s);
        assert!(p.is_on_curve());
    }

    #[test]
    fn subgroup_order() {
        // n*G should equal identity
        let g = BjjPoint::generator();
        let n = BjjScalar(field_from_dec_str::<Fr>(BJJ_ORDER));
        let result = g.scalar_mul(&n);
        assert!(result.is_zero(), "n*G must be identity");
    }
}
