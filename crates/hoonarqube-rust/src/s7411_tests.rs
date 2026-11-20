use super::*;

const CONTROLS: &str = include_str!("../fixtures/s7411_ranges.rs");

fn findings(source: &str) -> Vec<Issue> {
    analyze(
        PathBuf::from("ranges.rs"),
        source,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .filter(|issue| issue.rule_key == "rust:S7411")
    .collect()
}

fn span(start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> Range {
    Range {
        start: Pos {
            line: start_line,
            column: start_column,
        },
        end: Pos {
            line: end_line,
            column: end_column,
        },
    }
}

#[test]
fn s7411_two_block_primary_ranges_match_compiled_reference() {
    let expected = [
        (3, 4, 4, 19),
        (14, 4, 16, 19),
        (32, 4, 33, 5),
        (44, 4, 46, 5),
        (51, 4, 52, 19),
        // The separately observed else-if chain stays at its native range.
        (67, 11, 73, 5),
        (87, 4, 88, 19),
    ];
    for source in [CONTROLS.to_string(), CONTROLS.replace('\n', "\r\n")] {
        let issues = findings(&source);
        assert_eq!(issues.len(), expected.len());
        for (issue, (sl, sc, el, ec)) in issues.iter().zip(expected) {
            assert_eq!(issue.range, span(sl, sc, el, ec));
            assert_eq!(
                issue.message,
                "Refactor the code to avoid duplicating logic in multiple branches."
            );
            assert!(issue.flows.is_empty());
            assert!(issue.fix.is_none());
            assert!(issue.alternatives.is_empty());
        }
    }
}

#[test]
fn s7411_range_projection_keeps_unicode_columns_and_clean_controls() {
    let source = "fn f(flag: bool) {\n    if flag {\n        t(\"🦉\");\n        a();\n    } else {\n        t(\"🦉\");\n        b();\n    }\n}\n";
    let issues = findings(source);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].range, span(2, 4, 3, 15));
    for clean in [
        "fn f(flag: bool) { if flag { a(); } else { b(); } }",
        "fn f(flag: bool) -> i32 { if flag { let x = 1; x + 1 } else { let x = 2; x + 1 } }",
    ] {
        assert!(findings(clean).is_empty());
    }
}
