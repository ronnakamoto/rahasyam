fn main() {
    // Contract compilation is performed by the deployer at runtime immediately before
    // broadcasting. Running Forge from Cargo's build script makes Docker builds brittle
    // and duplicates work without producing Rust build artifacts.
    println!("cargo:rerun-if-changed=build.rs");
}
