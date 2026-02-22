use schnorr_core::{verify, KeyPair, Signature, VerifyResult};
use schnorr_witness::witness_builder;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut message = String::from("hello world");
    let mut output = PathBuf::from("build/input.json");

    // Simple argument parsing
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--message" | "-m" => {
                i += 1;
                if i < args.len() {
                    message = args[i].clone();
                }
            }
            "--output" | "-o" => {
                i += 1;
                if i < args.len() {
                    output = PathBuf::from(&args[i]);
                }
            }
            "--help" | "-h" => {
                eprintln!("Usage: schnorr-witness [OPTIONS]");
                eprintln!("  --message, -m  Message to sign (default: 'hello world')");
                eprintln!("  --output, -o   Output JSON path (default: build/input.json)");
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    eprintln!("[1/4] Generating keypair...");
    let keypair = KeyPair::generate();
    let (pk_x, pk_y) = keypair.pk.coords();
    eprintln!("  PK.x = {}", schnorr_core::curve::bn254_to_dec_string(&pk_x));
    eprintln!("  PK.y = {}", schnorr_core::curve::bn254_to_dec_string(&pk_y));

    eprintln!("[2/4] Signing message: {:?}", &message);
    let sig = Signature::sign(&keypair, message.as_bytes());
    eprintln!("  e = {}", schnorr_core::curve::bn254_to_dec_string(&sig.e));
    eprintln!("  s = {}", sig.s.to_dec_string());

    eprintln!("[3/4] Verifying signature (Rust)...");
    let result = verify(&sig, message.as_bytes(), &keypair.pk);
    assert_eq!(result, VerifyResult::Valid, "Rust verification failed!");
    eprintln!("  ✓ Signature valid");

    eprintln!("[4/4] Exporting witness JSON to {:?}...", &output);
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).expect("failed to create output directory");
    }
    witness_builder::export_witness_json(&sig, &keypair, message.as_bytes(), &output)
        .expect("failed to write witness JSON");

    // Also print the JSON to stdout for inspection
    let witness = witness_builder::build_witness_input(&sig, &keypair, message.as_bytes());
    println!("{}", serde_json::to_string_pretty(&witness).unwrap());
}
