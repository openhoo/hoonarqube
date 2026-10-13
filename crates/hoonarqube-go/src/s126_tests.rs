use super::{AnalyzerOptions, analyze};
use std::path::PathBuf;

const NESTED_IN_IF: &str = r"package p
func nested(enabled bool, c rune) {
    if enabled {
        count := 0
        for {
            if c == '{' {
                count++
            } else if c == '}' {
                count--
                if count == 0 {
                    break
                }
            }
        }
    }
}
";

const NESTED_IN_BRANCHES: &str = r"package p
func branches(a, b, c bool) {
    if a {
        if b { println(1) } else if c { println(2) }
    } else {
        if b { println(3) } else if c { println(4) }
    }
}
";

const NESTED_IN_INCOMPLETE_CHAIN: &str = r"package p
func chains(a, b, c bool) {
    if a {
        println(1)
    } else if b {
        if c { println(2) } else if a { println(3) }
    }
}
";

const TERMINATING_BRANCHES: &str = r#"package p
func returning(a, b bool) int {
    if a { return 1 } else if b { return 2; /* trailing comment */ }
    return 0
}
func jumping(a, b bool) {
outer:
    for {
        if a { break outer } else if b { continue outer }
        break
    }
}
func panicking(a, b bool) {
    if a { panic("first") } else if b { panic("second"); /* trailing comment */ }
}
func mixed(a, b bool) {
    for {
        if a { return } else if b { panic("second") } else if !a { break }
        break
    }
}
"#;

const NONTERMINATING_BRANCHES: &str = r#"package p
import "log"
func mixed(a, b bool) {
    if a { return } else if b { println(1) }
}
func deferred(a, b bool) {
    if a { defer panic("first") } else if b { defer panic("second") }
}
func qualified(a, b bool) {
    if a { log.Panic("first") } else if b { log.Panic("second") }
}
func early(a, b bool) {
    if a { return; println(1) } else if b { return }
}
func nestedReturn(a, b, c bool) {
    if a { if c { return } else { return } } else if b { return }
}
func jumping(a, b bool) {
    if a { goto done } else if b { goto done }
done:
    println(1)
}
"#;

const COMPLETE_CHAINS: &str = r"package p
func complete(a, b, c bool) {
    if a {
        if b { println(1) } else if c { println(2) } else { /* no action */ }
    } else if b {
        println(3)
    } else { /* no action */ }
    if c { println(4) }
}
";

fn findings(path: &str, source: &str) -> Vec<super::Issue> {
    let report = analyze(PathBuf::from(path), source, &AnalyzerOptions::default());
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.rule_key == "go:S2260"),
        "S126 control must parse: {report:?}"
    );
    report
        .issues
        .into_iter()
        .filter(|issue| issue.rule_key == "go:S126")
        .collect()
}

#[test]
fn reports_chain_nested_in_standalone_if_at_last_else_if() {
    let found = findings("nested.go", NESTED_IN_IF);
    assert_eq!(found.len(), 1, "independent nested chain: {found:?}");
    assert_eq!(found[0].message, "Add the missing \"else\" clause.");
    assert_eq!(
        (found[0].range.start.line, found[0].range.start.column),
        (8, 14)
    );
    assert_eq!(
        (found[0].range.end.line, found[0].range.end.column),
        (8, 21)
    );
}

#[test]
fn reports_independent_chains_in_both_branches() {
    let found = findings("branches.go", NESTED_IN_BRANCHES);
    assert_eq!(found.len(), 2, "both nested chains must report: {found:?}");
    assert_eq!(
        found
            .iter()
            .map(|issue| issue.range.start.line)
            .collect::<Vec<_>>(),
        [4, 6]
    );
}

#[test]
fn reports_outer_and_independent_nested_incomplete_chains_once() {
    let found = findings("chains.go", NESTED_IN_INCOMPLETE_CHAIN);
    assert_eq!(
        found.len(),
        2,
        "each independent chain reports once: {found:?}"
    );
    assert_eq!(
        found
            .iter()
            .map(|issue| issue.range.start.line)
            .collect::<Vec<_>>(),
        [5, 6]
    );
}

#[test]
fn exempts_only_chains_with_a_terminal_statement_in_every_branch() {
    let found = findings("terminating.go", TERMINATING_BRANCHES);
    assert!(
        found.is_empty(),
        "return, break, continue and direct panic chains: {found:?}"
    );
}

#[test]
fn preserves_nonterminal_and_nested_statement_boundaries() {
    let found = findings("nonterminating.go", NONTERMINATING_BRANCHES);
    assert_eq!(
        found.len(),
        6,
        "only the final direct statement can exempt a branch: {found:?}"
    );
    assert_eq!(
        found
            .iter()
            .map(|issue| issue.range.start.line)
            .collect::<Vec<_>>(),
        [4, 7, 10, 13, 16, 19]
    );
}

#[test]
fn permits_final_else_comments_and_single_if_statements() {
    assert!(findings("complete.go", COMPLETE_CHAINS).is_empty());
}

#[test]
fn evaluates_independent_chains_in_test_sources() {
    let found = findings("nested_test.go", NESTED_IN_IF);
    assert_eq!(found.len(), 1, "S126 declares ALL scope: {found:?}");
}
