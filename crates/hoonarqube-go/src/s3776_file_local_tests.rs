use std::path::PathBuf;

use hoonarqube_ir::{FileReport, Issue};

use crate::{AnalyzerOptions, analyze};

fn report(source: &str) -> FileReport {
    analyze(
        PathBuf::from("file_local.go"),
        source,
        &AnalyzerOptions {
            maximum_cognitive_complexity: 0,
            ..AnalyzerOptions::default()
        },
    )
}

fn complexity_issues(report: &FileReport) -> Vec<&Issue> {
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.rule_key == "go:S2260"),
        "valid syntax required: {:?}",
        report.issues
    );
    report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "go:S3776")
        .collect()
}

fn assert_score(source: &str, expected: usize) {
    let report = report(source);
    let issues = complexity_issues(&report);
    if expected == 0 {
        assert!(issues.is_empty(), "{source}\n{issues:?}");
    } else {
        assert_eq!(issues.len(), 1, "{source}\n{issues:?}");
        assert_eq!(
            issues[0].message,
            format!(
                "Refactor this method to reduce its Cognitive Complexity from {expected} to the 0 allowed."
            ),
            "{source}"
        );
    }
}

#[test]
fn s3776_file_local_method_error_returns_use_the_receiver_type() {
    assert_score(
        "package p\ntype Router struct{}\nfunc (*Router) fail() error { return nil }\nfunc check(router *Router) { problem := router.fail(); if problem != nil { println(problem) } }\n",
        0,
    );
    assert_score(
        "package p\ntype Router struct{}\nfunc (Router) fail() error { return nil }\nfunc check(router Router) { problem := router.fail(); if nil == problem { println(problem) } }\n",
        0,
    );
}

#[test]
fn s3776_file_local_declared_receivers_keep_method_results() {
    assert_score(
        "package p\ntype Router struct{}\nfunc (*Router) fail() error { return nil }\nfunc check() { var router *Router; problem := router.fail(); if problem != nil { println(problem) } }\n",
        0,
    );
}

#[test]
fn s3776_file_local_mux_walk_preserves_all_other_contributions() {
    let source = concat!(
        "package p\n",
        "type WalkFunc func(*Route, *Router, []*Route) error\n",
        "type Route struct { matchers []any; handler any }\n",
        "type Router struct { routes []*Route }\n",
        "var SkipRouter error\n",
        "func (r *Router) walk(walkFn WalkFunc, ancestors []*Route) error {\n",
        " for _, t := range r.routes {\n",
        "  err := walkFn(t, r, ancestors)\n",
        "  if err == SkipRouter { continue }\n",
        "  if err != nil { return err }\n",
        "  for _, sr := range t.matchers {\n",
        "   if h, ok := sr.(*Router); ok {\n",
        "    ancestors = append(ancestors, t)\n",
        "    err := h.walk(walkFn, ancestors)\n",
        "    if err != nil { return err }\n",
        "    ancestors = ancestors[:len(ancestors)-1]\n",
        "   }\n",
        "  }\n",
        "  if h, ok := t.handler.(*Router); ok {\n",
        "   ancestors = append(ancestors, t)\n",
        "   err := h.walk(walkFn, ancestors)\n",
        "   if err != nil { return err }\n",
        "   ancestors = ancestors[:len(ancestors)-1]\n",
        "  }\n",
        " }\n",
        " return nil\n",
        "}\n",
    );
    assert_score(source, 10);
    let report = report(source);
    let issues = complexity_issues(&report);
    let contributions: Vec<_> = issues[0]
        .flows
        .iter()
        .map(|flow| {
            assert_eq!(flow.locations.len(), 1);
            let location = &flow.locations[0];
            assert!(location.path.is_none());
            (
                location.range.start.line,
                location.range.start.column,
                location.range.end.column,
                location.message.as_str(),
            )
        })
        .collect();
    assert_eq!(
        contributions,
        vec![
            (7, 1, 4, "+1"),
            (9, 2, 4, "+2 (incl 1 for nesting)"),
            (11, 2, 5, "+2 (incl 1 for nesting)"),
            (12, 3, 5, "+3 (incl 2 for nesting)"),
            (19, 2, 4, "+2 (incl 1 for nesting)"),
        ]
    );
}

#[test]
fn s3776_file_local_query_unescape_error_result_is_exempt() {
    assert_score(
        "package p\nimport \"net/url\"\nfunc check() { _, problem := url.QueryUnescape(\"x\"); if problem != nil { println(problem) } }\n",
        0,
    );
}

#[test]
fn s3776_file_local_query_unescape_uses_the_import_alias() {
    assert_score(
        "package p\nimport uri \"net/url\"\nfunc check() { _, problem := uri.QueryUnescape(\"x\"); if nil == problem { println(problem) } }\n",
        0,
    );
}

#[test]
fn s3776_file_local_query_unescape_tuple_and_pointer_stay_distinct() {
    assert_score(
        "package p\nimport \"net/url\"\nfunc check() { value, problem := url.QueryUnescape(\"x\"); pointer := &value; if problem != nil { println(problem) }; if pointer != nil { println(pointer) } }\n",
        1,
    );
}

#[test]
fn s3776_file_local_guard_body_and_else_keep_their_control_flow() {
    assert_score(
        "package p\nimport \"net/url\"\nfunc check(flag bool) { _, problem := url.QueryUnescape(\"x\"); if problem != nil { if flag { println(problem) } } }\n",
        1,
    );
    assert_score(
        "package p\nimport \"net/url\"\nfunc check() { _, problem := url.QueryUnescape(\"x\"); if problem != nil { println(problem) } else { println(1) } }\n",
        2,
    );
}

#[test]
fn s3776_file_local_method_and_import_shadows_remain_positive() {
    for source in [
        "package p\ntype Router struct{}\ntype Other struct{}\nfunc (*Router) fail() error { return nil }\nfunc (*Other) fail() *int { return nil }\nfunc check(router *Other) { err := router.fail(); if err != nil { println(err) } }\n",
        "package p\ntype Router struct{}\nfunc (*Router) fail() error { return nil }\nfunc check(router interface { fail() *int }) { err := router.fail(); if err != nil { println(err) } }\n",
        "package p\ntype Router struct{}\nfunc (*Router) fail() error { return nil }\nfunc check() { type Router struct { fail func() *int }; var router *Router; err := router.fail(); if err != nil { println(err) } }\n",
        "package p\nimport \"net/url\"\nvar _ = url.QueryUnescape\nfunc check(url interface { QueryUnescape(string) (string, *int) }) { _, err := url.QueryUnescape(\"x\"); if err != nil { println(err) } }\n",
        "package p\nimport uri \"net/url\"\nvar _ = uri.QueryUnescape\nfunc check() { uri := struct { QueryUnescape func(string) (string, *int) }{}; _, err := uri.QueryUnescape(\"x\"); if err != nil { println(err) } }\n",
        "package p\nimport \"net/url\"\ntype error *int\nfunc check() { _, err := url.QueryUnescape(\"x\"); if err != nil { println(err) } }\n",
    ] {
        assert_score(source, 1);
    }
}

#[test]
fn s3776_file_local_selectors_and_cross_file_names_remain_counted() {
    assert_score(
        "package p\ntype Router struct { err error }\nfunc check(r *Router) { if r.err != nil { println(r.err) } }\n",
        1,
    );
    assert_score(
        "package p\nfunc check() { _, problem := newRouteRegexp(); if problem != nil { println(problem) } }\n",
        1,
    );
}

#[test]
fn s3776_file_local_malformed_source_keeps_the_parsing_finding() {
    let report = report(
        "package p\nimport \"net/url\"\nfunc check() { _, err := url.QueryUnescape(\"x\"); if err != nil {\n",
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.rule_key == "go:S2260")
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.rule_key == "go:S3776")
    );
}
