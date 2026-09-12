#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]
fn main() {
    let root = std::env::args().nth(1).expect("usage: dump-config <ignite-repo-root>");
    let cfg = ignite_config::load_config(std::path::Path::new(&root)).expect("load_config failed");
    // `Config` derives plain `Serialize` with no redaction — every secret
    // sub-struct (LLM API keys, GitHub/OIDC client secrets, SMTP password,
    // webhook secrets) instead has a hand-written `Debug` impl that
    // redacts those fields, which `serde_json::to_string_pretty` never
    // goes through. Printing via `{:#?}` uses that existing redaction
    // instead of dumping every secret in cleartext to stdout.
    println!("{cfg:#?}");
}
