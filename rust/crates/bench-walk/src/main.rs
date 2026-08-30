use std::env;
use std::time::Instant;

fn main() {
    let root = env::args().nth(1).expect("usage: bench-walk <root>");
    let root = std::path::PathBuf::from(root);

    let t0 = Instant::now();
    let files = ignite_fs_utils::walk_files(&root).expect("walk failed");
    let elapsed = t0.elapsed();

    println!("files: {}", files.len());
    println!("elapsed_ms: {}", elapsed.as_secs_f64() * 1000.0);
}
