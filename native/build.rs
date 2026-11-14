fn main() {
    // `cargo test` links libpython. asdf/pyenv builds publish that library as
    // `@rpath/libpython3.x.dylib` and do not put the directory on the default
    // dyld search path, so the test binary needs an rpath. No-op when
    // `extension-module` is set (maturin wheels do not link libpython).
    pyo3_build_config::add_libpython_rpath_link_args();

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
