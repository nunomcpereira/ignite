use std::collections::HashMap;
use std::time::Instant;

fn main() {
    let root = std::env::args().nth(1).expect("usage: bench-all <root>");
    let root = std::path::PathBuf::from(root);

    let t0 = Instant::now();

    let dc = ignite_dead_code::check_dead_code(&root, &ignite_dead_code::DeadCodeConfig { enabled: true }).unwrap();
    let t1 = Instant::now();

    let b = ignite_boundaries::check_boundaries(&root, &ignite_boundaries::BoundariesConfig { enabled: true, preset: Some("bulletproof".into()), zones: vec![] }).unwrap();
    let t2 = Instant::now();

    let css = ignite_css_dead_code::check_css_dead_code(&root, &ignite_css_dead_code::CssDeadCodeConfig { enabled: true }).unwrap();
    let t3 = Instant::now();

    let health = ignite_complexity_health::check_complexity_health(&root, &ignite_complexity_health::ComplexityHealthConfig::default(), &HashMap::new(), |_| None).unwrap();
    let t4 = Instant::now();

    let (secrets, _) = ignite_secrets::check_secrets(&root, &ignite_secrets::SecretsConfig::default(), &HashMap::new()).unwrap();
    let t5 = Instant::now();

    let (gov, _) = ignite_ai_governance::check_ai_governance(&root, &HashMap::new()).unwrap();
    let t6 = Instant::now();

    let fe = ignite_file_encapsulation::check_file_encapsulation(&root, &ignite_file_encapsulation::FileEncapsulationConfig { enabled: true, max_lines: 1000 }).unwrap();
    let t7 = Instant::now();

    let _cd = ignite_compliance_documents::check_compliance_documents(&root, true).unwrap();
    let t8 = Instant::now();

    println!("dead_code:       {:>8.2}ms  ({} findings)", (t1 - t0).as_secs_f64() * 1000.0, dc.findings.len());
    println!("boundaries:      {:>8.2}ms  ({} findings)", (t2 - t1).as_secs_f64() * 1000.0, b.findings.len());
    println!("css_dead_code:   {:>8.2}ms  ({} findings)", (t3 - t2).as_secs_f64() * 1000.0, css.findings.len());
    println!("complexity:      {:>8.2}ms  ({} findings)", (t4 - t3).as_secs_f64() * 1000.0, health.findings.len());
    println!("secrets:         {:>8.2}ms  ({} findings)", (t5 - t4).as_secs_f64() * 1000.0, secrets.findings.len());
    println!("ai_governance:   {:>8.2}ms  ({} findings)", (t6 - t5).as_secs_f64() * 1000.0, gov.findings.len());
    println!("file_encaps:     {:>8.2}ms  ({} findings)", (t7 - t6).as_secs_f64() * 1000.0, fe.findings.len());
    println!("compliance_docs: {:>8.2}ms", (t8 - t7).as_secs_f64() * 1000.0);
    println!("---");
    println!("TOTAL sequential: {:.2}ms", (t8 - t0).as_secs_f64() * 1000.0);
}
