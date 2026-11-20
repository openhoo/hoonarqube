use super::*;

fn findings(source: &str) -> Vec<Issue> {
    analyze(
        PathBuf::from("closures.rs"),
        source,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .filter(|i| i.rule_key == "rust:S1612")
    .collect()
}

#[test]
fn s1612_complete_reference_ranges_survive_method_ownership_and_layout_changes() {
    // The full set includes every compiler-accepted positive and also checks
    // absence on owned/deref-adjusted receivers, a block and captured values.
    let issues = findings(include_str!("../fixtures/s1612_methods.rs"));
    let ranges = issues
        .iter()
        .map(|i| {
            (
                i.range.start.line,
                i.range.start.column,
                i.range.end.line,
                i.range.end.column,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ranges,
        [
            (5, 31, 5, 51),
            (9, 31, 9, 51),
            (13, 35, 13, 55),
            (18, 13, 20, 31),
            (24, 18, 24, 43),
            (30, 14, 30, 34),
            (33, 51, 33, 62),
            (36, 14, 36, 25)
        ]
    );
    assert!(
        issues
            .iter()
            .all(|i| i.message == "Replace this closure with a method reference.")
    );
}

#[test]
fn s1612_rejects_unproven_constructors_shadowed_bindings_and_unrelated_calls() {
    let controls = [
        "fn f(value: Option<&char>) { let _ = value.map(|c| c.to_uppercase()); }",
        "fn f(value: Option<char>, other: Option<&char>) { let value = other; let _ = value.map(|c| c.to_uppercase()); }",
        "fn f(value: Option<char>, other: Option<Option<&char>>) { if let Some(value) = other { let _ = value.map(|c| c.to_uppercase()); } }",
        "fn f(value: Option<char>, other: &[Option<&char>]) { for value in other { let _ = value.map(|c| c.to_uppercase()); } }",
        "fn f() { let _ = Some('a').map(|c| c.to_uppercase()); } fn Some(_:char) -> Option<&'static char> { None }",
        "fn f() { let _ = Some('a').map(|c| c.to_uppercase()); } use self::other::*; mod other { pub fn Some(_:char) -> Option<&'static char> { None } }",
        "fn f(a: Option<char>) { let cb = |x:Option<&char>| x.map(|c| c.to_uppercase()); let _=cb(None); }",
        "use std::string::String as char; fn f(x: Option<char>) { let _=x.map(|s| s.to_uppercase()); }",
        "mod outer { use std::thread as t; fn f() { use std::num as t; let _=t::available_parallelism().map(|n| n.get()); } }",
        "use std::thread as threads; mod std { pub mod thread { pub fn available_parallelism()->Option<String>{None} } } fn f(){let _=threads::available_parallelism().map(|v| v.get());}",
        "fn f(x: Option<String>) { let _=x.map(|s| s.len()); }",
        "fn f() { let _=Some('a').map(|c| c.to_uppercase().to_string()); }",
        "fn f() { let _=Some('a').map(|c| { c.to_uppercase() }); }",
        "fn f() { let _=Some('a').map(char::to_uppercase); }",
    ];
    for source in controls {
        assert!(findings(source).is_empty(), "{source}");
    }
}

#[test]
fn s1612_uses_the_actual_outer_adapter_and_its_visible_input() {
    for source in [
        "fn f() { let x = Some('ß'); let _ = x.map(|letter| letter.to_uppercase()); }",
        "fn f(x: ::core::option::Option<char>) { let _ = x.map(|letter| letter.to_lowercase()); }",
        "use std::thread as threads; fn f() { let _ = threads::available_parallelism().map_or(1, |n| n.get()); }",
    ] {
        assert_eq!(findings(source).len(), 1, "{source}");
    }
}

#[test]
fn s1612_char_method_pointers_have_compatible_value_receivers() {
    let source = include_str!("../fixtures/s1612_char_methods.rs");
    let rows = findings(source);
    assert_eq!(rows.len(), 14);
    for issue in rows {
        let line = source
            .lines()
            .nth(issue.range.start.line as usize - 1)
            .unwrap();
        assert!(line.contains("map(|c| c."), "{line}");
    }
    assert!(findings("fn f() { let _=Some('A').map(|c| c.is_ascii_digit()); }").is_empty());
}

#[test]
fn s1612_recognizes_the_available_parallelism_idioms_in_ripgrep_and_rayon() {
    let source = include_str!("../fixtures/s1612_project_expressions.rs");
    let ranges = findings(source)
        .into_iter()
        .map(|i| (i.range.start.line, i.range.start.column, i.range.end.column))
        .collect::<Vec<_>>();
    assert_eq!(ranges, [(3, 51, 62), (7, 13, 24)]);
}
