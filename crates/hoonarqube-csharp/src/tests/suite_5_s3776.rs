//! Test suite part; the full suite spans `tests/*.rs`.

use super::{analyze_default, with_key};
use std::fmt::Write as _;

#[test]
fn s3776_wrapper_does_not_inherit_nested_static_local_complexity() {
    let mut body = String::new();
    for step in 1..=16 {
        let _ = writeln!(
            body,
            "            if (value > {step}) {{ total = {step}; }}"
        );
    }
    let source = format!(
        "class Pipeline\n{{\n    int Run(int seed)\n    {{\n        static int Impl(int value)\n        {{\n            var total = 0;\n{body}            return total;\n        }}\n        return Impl(seed);\n    }}\n}}\n"
    );
    let report = analyze_default(&source);
    let flagged = with_key(&report, "csharpsquid:S3776");
    assert_eq!(
        flagged.len(),
        1,
        "only the static local function's own finding remains: {:?}",
        flagged
            .iter()
            .map(|issue| issue.range.start.line)
            .collect::<Vec<_>>()
    );
    assert_eq!(flagged[0].range.start.line, 5);
    assert!(flagged[0].message.contains("from 16 to the 15 allowed"));
}

#[test]
fn s4019_requires_compatible_signatures_before_reporting_hidden_base_methods() {
    let source = "interface IStore\n{\n    object Load(System.Type kind, object raw);\n}\nabstract class Store<T> : IStore\n{\n    public abstract T Load(object raw);\n    object IStore.Load(System.Type kind, object raw) => Load(raw);\n}\nabstract class StringStore<T> : Store<T>\n{\n    protected abstract T Load(string raw);\n}\n";
    let report = analyze_default(source);
    assert!(
        with_key(&report, "csharpsquid:S4019").is_empty(),
        "different-signature overloads are not hidden base methods"
    );
}

#[test]
fn s4019_derived_narrower_parameters_do_not_hide_base_methods() {
    let source = "class Base\n{\n    public int Send(object message) => 0;\n}\nclass Derived : Base\n{\n    public int Send(string message) => 1;\n}\n";
    let report = analyze_default(source);
    assert!(
        with_key(&report, "csharpsquid:S4019").is_empty(),
        "a narrower derived overload leaves the base method callable"
    );
}

#[test]
fn s4019_still_reports_genuine_hidden_base_methods() {
    let same_signature = "class Base\n{\n    public int Send(string message) => 0;\n}\nclass Derived : Base\n{\n    public int Send(string message) => 1;\n}\n";
    let same_report = analyze_default(same_signature);
    let flagged = with_key(&same_report, "csharpsquid:S4019");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);
    assert_eq!(
        flagged[0].message,
        "Remove or rename that method because it hides 'Base.Send(string)'."
    );

    let wider_derived = "class Base\n{\n    public int Send(string message) => 0;\n}\nclass Derived : Base\n{\n    public int Send(object message) => 1;\n}\n";
    let wider_report = analyze_default(wider_derived);
    let flagged = with_key(&wider_report, "csharpsquid:S4019");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);
    assert_eq!(
        flagged[0].message,
        "Remove or rename that method because it hides 'Base.Send(string)'."
    );
}

#[test]
fn s4136_ignores_trivia_and_non_method_members_when_grouping_overloads() {
    let source = "class Api\n{\n    // leading comment\n    void Save(int value) { }\n\n    /// doc comment\n    int Draft { get; set; }\n\n    // trailing comment\n    void Save(string value) { }\n}\n";
    let report = analyze_default(source);
    assert!(
        with_key(&report, "csharpsquid:S4136").is_empty(),
        "comments and non-method members do not split overload groups"
    );
}

#[test]
fn s4136_explicit_interface_methods_do_not_split_overload_groups() {
    let source = "interface I\n{\n    void M(int value);\n}\nclass C : I\n{\n    public void M(int value) { }\n    void I.M(int value) { }\n    public void M(string value) { }\n}\n";
    let report = analyze_default(source);
    assert!(
        with_key(&report, "csharpsquid:S4136").is_empty(),
        "explicit interface implementations do not break overload adjacency"
    );
}

#[test]
fn s4136_still_reports_method_separated_overload_groups() {
    let source = "class Report\n{\n    void Emit(int value) { }\n    void Flush() { }\n    void Emit(string value) { }\n    void Flush(int value) { }\n}\n";
    let report = analyze_default(source);
    let flagged = with_key(&report, "csharpsquid:S4136");
    assert_eq!(flagged.len(), 2, "unrelated groups stay independent");
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 4);
}
