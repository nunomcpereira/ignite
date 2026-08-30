fn main() {
    let root = std::env::args().nth(1).expect("usage: dump-config <ignite-repo-root>");
    let cfg = ignite_config::load_config(std::path::Path::new(&root)).expect("load_config failed");
    println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
}
