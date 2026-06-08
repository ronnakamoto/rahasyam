//! Regenerate `../vectors/client_ref.json` from the real Nightfish primitives.
//!
//! ```sh
//! cargo run --example gen_vectors
//! ```

use std::path::PathBuf;

fn main() {
    let v = nightfish_honk_ref::reference_vector_json();
    let json = serde_json::to_string_pretty(&v).expect("serialize vectors");

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/client_ref.json");
    std::fs::write(&out, format!("{json}\n")).expect("write client_ref.json");
    println!("wrote {}", out.display());
    println!("{json}");
}
