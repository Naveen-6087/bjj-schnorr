use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::path::Path;

use schnorr_core::hash::hash_message_to_field;
use schnorr_core::keypair::KeyPair;
use schnorr_core::sign::Signature;

/// Convert any PrimeField element to a decimal string for Circom JSON.
fn field_to_dec<F: PrimeField>(f: &F) -> String {
    let bytes = f.into_bigint().to_bytes_le();
    BigUint::from_bytes_le(&bytes).to_string()
}

pub fn build_witness_input(sig: &Signature, keypair: &KeyPair, message: &[u8]) -> Value {
    let msg_hash = hash_message_to_field(message);
    let (pk_x, pk_y) = keypair.pk.coords();

    // s is ark_ed_on_bn254::Fr — its integer value is < n < p,
    // so the decimal string is the same whether viewed in Z_n or F_p.
    let s_dec = field_to_dec(&sig.s.0);

    // e is ark_bn254::Fr — already in F_p.
    let e_dec = field_to_dec(&sig.e);

    json!({
        "pkX":     field_to_dec(&pk_x),
        "pkY":     field_to_dec(&pk_y),
        "msgHash": field_to_dec(&msg_hash),
        "s":       s_dec,
        "e":       e_dec,
    })
}

/// Build witness JSON and write it to a file.
pub fn export_witness_json(
    sig: &Signature,
    keypair: &KeyPair,
    message: &[u8],
    output_path: &Path,
) -> std::io::Result<()> {
    let witness = build_witness_input(sig, keypair, message);
    let json_str = serde_json::to_string_pretty(&witness).expect("JSON serialization failed");
    std::fs::write(output_path, json_str)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_json_has_correct_keys() {
        let kp = KeyPair::generate();
        let msg = b"test";
        let sig = Signature::sign(&kp, msg);

        let json = build_witness_input(&sig, &kp, msg);
        let obj = json.as_object().unwrap();

        assert!(obj.contains_key("pkX"), "missing pkX");
        assert!(obj.contains_key("pkY"), "missing pkY");
        assert!(obj.contains_key("msgHash"), "missing msgHash");
        assert!(obj.contains_key("s"), "missing s");
        assert!(obj.contains_key("e"), "missing e");
    }

    #[test]
    fn witness_values_are_decimal_strings() {
        let kp = KeyPair::generate();
        let msg = b"test";
        let sig = Signature::sign(&kp, msg);

        let json = build_witness_input(&sig, &kp, msg);

        // All values should parse as valid BigUint decimals
        for key in &["pkX", "pkY", "msgHash", "s", "e"] {
            let val = json[key].as_str().unwrap_or_else(|| panic!("{key} is not a string"));
            val.parse::<BigUint>()
                .unwrap_or_else(|_| panic!("{key} is not a valid decimal: {val}"));
        }
    }

    #[test]
    fn witness_deterministic() {
        let kp = KeyPair::generate();
        let msg = b"deterministic";
        let sig = Signature::sign(&kp, msg);

        let j1 = build_witness_input(&sig, &kp, msg);
        let j2 = build_witness_input(&sig, &kp, msg);
        assert_eq!(j1, j2);
    }
}
