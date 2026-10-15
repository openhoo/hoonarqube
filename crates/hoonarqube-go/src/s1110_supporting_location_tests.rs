//! S1110 actual inner-closing-token regressions from SonarQube26.9 / Go1.43.
//! Exact source bytes: supplemental proposal8cb0f133f42ab609beaf7ef880a180ba593fed5e6902546af81d4ebf1a19c747.
//! Actual raw supporting msg is absent; existing IR represents it as empty.
use super::{AnalyzerOptions, FlowLocation, Issue, Pos, Range, analyze};
use std::path::PathBuf;

fn range([sl, sc, el, ec]: [u32; 4]) -> Range {
    Range {
        start: Pos {
            line: sl,
            column: sc,
        },
        end: Pos {
            line: el,
            column: ec,
        },
    }
}

fn expected(primary: [u32; 4], support: [u32; 4]) -> Issue {
    Issue::new(
        "go:S1110",
        "Remove these useless parentheses.",
        range(primary),
    )
    .with_flow(vec![FlowLocation::in_primary_file("", range(support))])
}

fn assert_findings(source: &str, expected: &[Issue]) {
    let report = analyze(
        PathBuf::from("case.go"),
        source,
        &AnalyzerOptions::default(),
    );
    let actual: Vec<_> = report
        .issues
        .into_iter()
        .filter(|issue| issue.rule_key == "go:S1110")
        .collect();
    assert_eq!(actual.as_slice(), expected);
}

#[test]
fn s1110_original_three_inner_closing_locations() {
    assert_findings(
        SOURCE_1,
        &[
            expected([5, 8, 5, 9], [5, 18, 5, 19]),
            expected([7, 11, 7, 12], [7, 19, 7, 20]),
            expected([8, 12, 8, 13], [8, 18, 8, 19]),
        ],
    );
}

#[test]
fn s1110_single_parentheses_are_clean() {
    assert_findings(SOURCE_2, &[]);
}

#[test]
fn s1110_multiline_inner_close() {
    assert_findings(SOURCE_3, &[expected([5, 12, 5, 13], [6, 13, 6, 14])]);
}

#[test]
fn s1110_astral_crlf_scalar_coordinates() {
    assert_findings(SOURCE_4, &[expected([5, 23, 5, 24], [5, 29, 5, 30])]);
}

#[test]
fn s1110_triple_nesting_pairs_each_inner_child() {
    assert_findings(
        SOURCE_5,
        &[
            expected([5, 12, 5, 13], [5, 20, 5, 21]),
            expected([5, 13, 5, 14], [5, 19, 5, 20]),
        ],
    );
}

#[test]
fn s1110_independent_pairs_keep_order() {
    assert_findings(
        SOURCE_6,
        &[
            expected([5, 12, 5, 13], [5, 18, 5, 19]),
            expected([5, 24, 5, 25], [5, 30, 5, 31]),
        ],
    );
}

#[test]
fn s1110_comment_closing_decoys_use_syntax_token() {
    assert_findings(SOURCE_7, &[expected([5, 12, 5, 13], [5, 18, 5, 19])]);
}

#[test]
fn s1110_literal_and_comment_decoys_are_clean() {
    assert_findings(SOURCE_8, &[]);
}

#[test]
fn s1110_malformed_source_keeps_parsing_failure() {
    assert_findings(SOURCE_9, &[]);
    let report = analyze(
        PathBuf::from("case.go"),
        SOURCE_9,
        &AnalyzerOptions::default(),
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.rule_key == "go:S2260")
    );
}

const SOURCE_1: &str = "// Hoonarqube oracle fixture: go:S1110 bad\npackage oracle\n\nfunc foo(a bool, y int) int {\n  x := ((y / 2 + 1)) // Noncompliant\n\n  if a && ((x+y > 0)) {  // Noncompliant\n    return ((x + 1))  // Noncompliant\n  }\n}\n";
const SOURCE_2: &str = "// Hoonarqube oracle fixture: go:S1110 good\npackage oracle\n\nfunc foo(a bool, y int) int {\n  x := (y / 2 + 1)\n\n  if a && (x+y > 0) {\n    return (x + 1)\n  }\n}\n";
const SOURCE_3: &str =
    "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((\n        x + 1))\n}\n";
const SOURCE_4: &str = "// Licensed\r\npackage p\r\n\r\nfunc f(x int) int {\r\n    return len(\"😀\") + ((x + 1))\r\n}\r\n";
const SOURCE_5: &str = "// Licensed\npackage p\n\nfunc f(x int) int {\n    return (((x + 1)))\n}\n";
const SOURCE_6: &str =
    "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((x + 1)) + ((x + 2))\n}\n";
const SOURCE_7: &str = "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((x + 1) /* ) )) marker only */)\n}\n";
const SOURCE_8: &str = "// Licensed\npackage p\n\nfunc f() string {\n    // ((comment)) ) (\n    return \"((literal)) ) (\"\n}\n";
const SOURCE_9: &str = "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((x + 1)\n}\n";
