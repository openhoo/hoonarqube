use std::path::Path;

use hoonarqube::{AnalyzerOptions, analyze, language_for_path};

#[test]
fn public_facade_routes_registered_paths_and_rejects_unknown_extensions() {
    let fixtures = [
        ("fixture.py", "x = 1\n", "python"),
        ("fixture.js", "eval('x');\n", "javascript"),
        ("fixture.ts", "eval('x');\n", "typescript"),
        ("fixture.cs", "\tint x;\nclass A\n{\n}\n", "csharpsquid"),
        ("fixture.go", "package p\nfunc bad_name() {}\n", "go"),
        ("fixture.java", "class Main { void f() {} }\n", "java"),
        ("fixture.rb", "def f\n  value.length\nend\n", "ruby"),
        ("fixture.rs", "fn main() { println!(\"hello\"); }\n", "rust"),
    ];

    for (path, source, language) in fixtures {
        let path = Path::new(path);
        assert!(
            language_for_path(path).is_some(),
            "{path:?} should dispatch"
        );
        let report = analyze(path, source, &AnalyzerOptions::default())
            .unwrap_or_else(|| panic!("{path:?} should produce a report"));
        assert_eq!(report.language, language);
    }

    assert!(language_for_path(Path::new("fixture.unknown")).is_none());
}

#[test]
fn public_facade_exposes_catalog_for_routed_findings() {
    let report = analyze(
        Path::new("fixture.py"),
        "x = 1 \n",
        &AnalyzerOptions::default(),
    )
    .expect("Python should dispatch through the facade");
    assert!(!report.issues.is_empty());

    let catalog = hoonarqube::catalog::embedded();
    for issue in &report.issues {
        assert!(
            catalog.rule(&issue.rule_key).is_some(),
            "facade catalog should resolve {}",
            issue.rule_key
        );
    }
}
