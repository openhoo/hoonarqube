//! Observable S3776 primary and supporting-location regressions.

use std::path::PathBuf;

use hoonarqube_ir::{Issue, Pos, Range};

use crate::{AnalyzerOptions, analyze};

fn complexity_findings(source: &str, maximum: usize) -> Vec<Issue> {
    let options = AnalyzerOptions {
        maximum_cognitive_complexity: maximum,
        ..AnalyzerOptions::default()
    };
    analyze(PathBuf::from("complexity.rs"), source, &options)
        .issues
        .into_iter()
        .filter(|issue| issue.rule_key == "rust:S3776")
        .collect()
}

fn projection(issue: &Issue) -> Vec<(Range, &str)> {
    issue
        .flows
        .iter()
        .map(|flow| {
            assert_eq!(
                flow.locations.len(),
                1,
                "each increment is a singleton flow"
            );
            let location = &flow.locations[0];
            assert_eq!(location.path, None);
            (location.range.clone(), location.message.as_str())
        })
        .collect()
}

fn span(line: u32, start: u32, end: u32) -> Range {
    Range {
        start: Pos {
            line,
            column: start,
        },
        end: Pos { line, column: end },
    }
}

const NESTED_SOURCE: &str = concat!(
    "fn compute(a: bool, b: bool, c: bool) {\n",
    "    if a && b && c {\n",
    "        while b || c { break; }\n",
    "    } else if b {\n",
    "        match c { true => (), false => () }\n",
    "    } else {\n",
    "        for _ in 0..3 {\n",
    "            loop { break; }\n",
    "        }\n",
    "    }\n",
    "}\n",
);

#[test]
fn s3776_supporting_ranges_cover_keywords_logical_runs_and_else_links() {
    let issues = complexity_findings(NESTED_SOURCE, 13);
    assert_eq!(issues.len(), 1);
    let issue = &issues[0];
    assert_eq!(issue.range, span(1, 3, 10));
    assert_eq!(
        issue.message,
        "Refactor this function to reduce its Cognitive Complexity from 14 to the 13 allowed."
    );
    assert_eq!(
        projection(issue),
        vec![
            (span(2, 4, 6), "+1"),
            // Sonar's left-associative same-operator run is attached to its
            // outer/rightmost operator, not both && tokens.
            (span(2, 14, 16), "+1"),
            (span(3, 8, 13), "+2 (incl 1 for nesting)"),
            (span(3, 16, 18), "+1"),
            // The else-if link contributes once at else, not once at each token.
            (span(4, 6, 10), "+1"),
            (span(5, 8, 13), "+2 (incl 1 for nesting)"),
            (span(6, 6, 10), "+1"),
            (span(7, 8, 11), "+2 (incl 1 for nesting)"),
            (span(8, 12, 16), "+3 (incl 2 for nesting)"),
        ]
    );
    assert!(complexity_findings(NESTED_SOURCE, 14).is_empty());
}

#[test]
fn s3776_supporting_ranges_preserve_utf8_columns_and_crlf_lines() {
    let source = "fn f(a: bool) {\n    let café = \"😀\"; if a { if a {} }\n}\n";
    for text in [source.to_owned(), source.replace('\n', "\r\n")] {
        let issues = complexity_findings(&text, 2);
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Refactor this function to reduce its Cognitive Complexity from 3 to the 2 allowed."
        );
        assert_eq!(
            projection(&issues[0]),
            vec![
                (span(2, 20, 22), "+1"),
                (span(2, 27, 29), "+2 (incl 1 for nesting)"),
            ]
        );
    }
}

#[test]
fn s3776_supporting_locations_retain_every_repeated_increment() {
    let mut source = String::from("fn f(a: bool) {\n");
    for _ in 0..16 {
        source.push_str("    if a {}\n");
    }
    source.push_str("}\n");
    let issues = complexity_findings(&source, 15);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0].message,
        "Refactor this function to reduce its Cognitive Complexity from 16 to the 15 allowed."
    );
    let expected: Vec<_> = (2..=17).map(|line| (span(line, 4, 6), "+1")).collect();
    assert_eq!(projection(&issues[0]), expected);
    assert!(complexity_findings(&source, 16).is_empty());
}

#[test]
fn s3776_clean_and_threshold_controls_do_not_create_findings() {
    assert!(
        complexity_findings(
            "fn clean() { let text = \"if else && ||\"; /* if true { } */ }",
            0
        )
        .is_empty()
    );
    assert!(complexity_findings("fn f(a: bool) { if a {} }", 1).is_empty());
    assert!(complexity_findings(NESTED_SOURCE, 14).is_empty());
}
