//! S107 supporting locations measured with SonarQube 26.9 / Go 1.43.
//! Root qualification: 73f163049214ce13e7b1a114ad34c31ceca421a5029a0ef0083b30d80e818ec4.
//! Raw reference support messages are absent; existing IR stores empty strings.
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

fn expected(count: usize, maximum: usize, primary: [u32; 4], supports: &[[u32; 4]]) -> Issue {
    let mut issue = Issue::new(
        "go:S107",
        format!(
            "This function has {count} parameters, which is greater than the {maximum} authorized."
        ),
        range(primary),
    );
    for support in supports {
        issue = issue.with_flow(vec![FlowLocation::in_primary_file("", range(*support))]);
    }
    issue
}

fn assert_findings(source: &str, maximum: usize, expected: &[Issue]) {
    let report = analyze(
        PathBuf::from("case.go"),
        source,
        &AnalyzerOptions {
            maximum_function_parameters: maximum,
            ..AnalyzerOptions::default()
        },
    );
    let actual: Vec<_> = report
        .issues
        .into_iter()
        .filter(|issue| issue.rule_key == "go:S107")
        .collect();
    assert_eq!(actual.as_slice(), expected);
}

#[test]
fn s107_unprobed_parameter_shapes_refuse_supports_without_removing_primary() {
    // Conservative native refusal controls, not reference parity assertions.
    for source in [
        "package p\nfunc unnamed(int,int,int,int,int,int,int,int) { println(0) }\n",
        "package p\nfunc blank(a,b,c,d,e,f,g,_ int) { println(a) }\n",
        "package p\nfunc functionTyped(a,b,c,d,e,f,g int,h func(x int)) { println(a) }\n",
        "package p\nfunc generic[T any](a,b,c,d,e,f,g,h T) { println(a) }\n",
    ] {
        let report = analyze(
            PathBuf::from("case.go"),
            source,
            &AnalyzerOptions::default(),
        );
        let issues: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "go:S107")
            .collect();
        assert_eq!(issues.len(), 1, "{source}");
        assert_eq!(
            issues[0].message,
            "This function has 8 parameters, which is greater than the 7 authorized."
        );
        assert!(issues[0].flows.is_empty(), "{source}");
    }
}

#[test]
fn s107_malformed_parameters_keep_parsing_failure_and_refuse_supports() {
    let source = "package p\nfunc broken(a,b,c,d,e,f,g,h int, ?) { println(a) }\n";
    let report = analyze(
        PathBuf::from("case.go"),
        source,
        &AnalyzerOptions::default(),
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.rule_key == "go:S2260")
    );
    assert!(
        report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "go:S107")
            .all(|issue| issue.flows.is_empty())
    );
}

#[test]
fn s107_default_01_separated_eight() {
    assert_findings(
        "package probe\nfunc separatedEight(a int,b int,c int,d int,e int,f int,g int,h int) { println(a,b,c,d,e,f,g,h) }\n",
        7,
        &[expected(8, 7, [2, 5, 2, 19], &[[2, 62, 2, 67]])],
    );
}

#[test]
fn s107_default_02_separated_nine() {
    assert_findings(
        "package probe\nfunc separatedNine(a int,b int,c int,d int,e int,f int,g int,h int,i int) { println(a,b,c,d,e,f,g,h,i) }\n",
        7,
        &[expected(
            9,
            7,
            [2, 5, 2, 18],
            &[[2, 61, 2, 66], [2, 67, 2, 72]],
        )],
    );
}

#[test]
fn s107_default_03_grouped_nine() {
    assert_findings(
        "package probe\nfunc groupedNine(a,b,c,d,e,f,g,h,i int) { println(a,b,c,d,e,f,g,h,i) }\n",
        7,
        &[expected(
            9,
            7,
            [2, 5, 2, 16],
            &[[2, 31, 2, 32], [2, 33, 2, 38]],
        )],
    );
}

#[test]
fn s107_default_04_mixed_group() {
    assert_findings(
        "package probe\nfunc mixedGroups(a,b,c,d,e,f int,g,h,i string) { println(a,b,c,d,e,f,g,h,i) }\n",
        7,
        &[expected(
            9,
            7,
            [2, 5, 2, 16],
            &[[2, 35, 2, 36], [2, 37, 2, 45]],
        )],
    );
}

#[test]
fn s107_default_05_method_boundary() {
    assert_findings(
        "package probe\ntype Receiver struct{}\nfunc (r Receiver) methodSeven(a,b,c,d,e,f,g int) { println(a,b,c,d,e,f,g) }\nfunc (r Receiver) methodEight(a,b,c,d,e,f,g,h int) { println(a,b,c,d,e,f,g,h) }\n",
        7,
        &[expected(8, 7, [4, 18, 4, 29], &[[4, 44, 4, 49]])],
    );
}

#[test]
fn s107_default_06_literal_existing_primary_preserved() {
    assert_findings(
        "package probe\nvar literal = func(a,b,c,d,e,f,g,h int) { println(a,b,c,d,e,f,g,h) }\n",
        7,
        &[expected(8, 7, [2, 18, 2, 39], &[[2, 33, 2, 38]])],
    );
}

#[test]
fn s107_default_07_variadic_existing_variadic_omission_preserved() {
    assert_findings(
        "package probe\nfunc variadic(a,b,c,d,e,f,g int,h ...int) { println(a,b,c,d,e,f,g,h) }\n",
        7,
        &[],
    );
}

#[test]
fn s107_default_08_negative_and_position() {
    assert_findings(
        "package probe\r\nfunc boundarySeven(a,b,c,d,e,f,g int) { println(a,b,c,d,e,f,g) }\r\n/* 😀 */ func positionEight(\r\n a,b,c,d,e,f,g,\r\n h int,\r\n) { println(a,b,c,d,e,f,g,h) }\r\n",
        7,
        &[expected(8, 7, [3, 13, 3, 26], &[[5, 1, 5, 6]])],
    );
}

#[test]
fn s107_custom_max2_01_custom_grouped() {
    assert_findings(
        "package probe\nfunc customGrouped(a,b,c int) { println(a,b,c) }\n",
        2,
        &[expected(3, 2, [2, 5, 2, 18], &[[2, 23, 2, 28]])],
    );
}

#[test]
fn s107_custom_max2_01_custom_grouped_native_max7_remains_clean() {
    assert_findings(
        "package probe\nfunc customGrouped(a,b,c int) { println(a,b,c) }\n",
        7,
        &[],
    );
}

#[test]
fn s107_custom_max2_02_custom_separated() {
    assert_findings(
        "package probe\nfunc customSeparated(a int,b int,c int) { println(a,b,c) }\n",
        2,
        &[expected(3, 2, [2, 5, 2, 20], &[[2, 33, 2, 38]])],
    );
}

#[test]
fn s107_custom_max2_02_custom_separated_native_max7_remains_clean() {
    assert_findings(
        "package probe\nfunc customSeparated(a int,b int,c int) { println(a,b,c) }\n",
        7,
        &[],
    );
}

#[test]
fn s107_original_grouped8_excess_span() {
    assert_findings(
        "// Hoonarqube oracle fixture: go:S107 bad\npackage oracle\nfunc many(a,b,c,d,e,f,g,h int) { println(a,b,c,d,e,f,g,h) }\n",
        7,
        &[expected(8, 7, [3, 5, 3, 9], &[[3, 24, 3, 29]])],
    );
}

#[test]
fn s107_original_boundary7_clean() {
    assert_findings(
        "// Hoonarqube oracle fixture: go:S107 good\npackage oracle\n\n// Each function does a part of what the original setCoordinates function was doing, so confusion risks are lower\nfunc setOrigin(x int, y int, z int) {\n   // ...\n}\n\nfunc setSize(width int, height int, depth int) {\n   // ...\n}\n",
        7,
        &[],
    );
}
