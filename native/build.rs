fn main() {
    // Pin matches native/Cargo.toml (`whiff = "=0.8.0"`). A test reads this env.
    println!("cargo:rustc-env=WHIFF_CRATE_VERSION=0.8.0");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=WHIFF_FEATURES");

    // Cargo cannot turn an env var into dependency features. When the var is
    // set to something other than the default collection, say how to pass it.
    if let Ok(value) = std::env::var("WHIFF_FEATURES") {
        let value = value.trim();
        if !value.is_empty() && value != "common" {
            println!(
                "cargo:warning=WHIFF_FEATURES={value} is selected by cargo features; build with `maturin develop --features {value}`"
            );
        }
    }
}
