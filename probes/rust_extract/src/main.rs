//! Extract one path with the same options the golden test uses (`hashes: none`).

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: whiff_rust_extract_probe <path>");
    let engine = whiff::Engine::builder().hashes(whiff::Hashes::NONE).build();
    let report = engine.extract_path(&path).unwrap_or_else(|err| {
        eprintln!("extract failed: {err}");
        std::process::exit(1);
    });
    println!(
        "{}",
        serde_json::to_string(&report).expect("report serializes")
    );
}
