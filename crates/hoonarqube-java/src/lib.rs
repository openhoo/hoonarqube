//! Tolerant tree-sitter Java frontend.
//!
//! bounded intraprocedural flow foundation and a conservative set of
//! syntax/scope-feasible GitHub Code Quality checks. It does not pretend to
//! have a Java classpath or compiler type model, and emits no guessed facts.

use std::path::PathBuf;

use hoonarqube_ir::{FileMetrics, FileReport, Issue, u32_saturating};
mod context;
mod engine;
mod support;

pub use context::{
    ImportFact, ScopeId, ScopeKind, SemanticIndex, Symbol, SymbolId, SymbolKind, TypeFact,
};
pub use engine::{CfgNode, ControlFlowGraph, DataflowSummary, Definition, MethodFlow, NodeId};
pub use support::LineIndex;

/// Configuration for the Java frontend. These thresholds are retained for
/// rule modules as they are registered; defaults are intentionally inert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
    pub maximum_file_loc_threshold: u32,
    pub maximum_function_parameters: u32,
    pub maximum_function_lines: u32,
    pub maximum_nesting_level: u32,
    pub maximum_cognitive_complexity: u32,
    pub maximum_expression_complexity: u32,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 180,
            maximum_file_loc_threshold: 1000,
            maximum_function_parameters: 7,
            maximum_function_lines: 80,
            maximum_nesting_level: 3,
            maximum_cognitive_complexity: 15,
            maximum_expression_complexity: 3,
        }
    }
}

/// Parses one Java source file and returns metrics plus currently registered
/// findings. Syntax errors fail closed and never produce fabricated issues.
#[must_use]
pub fn analyze(path: PathBuf, source: &str, _options: &AnalyzerOptions) -> FileReport {
    let Some(tree) = context::parse(source) else {
        return FileReport {
            path,
            language: "java".to_owned(),
            issues: Vec::new(),
            metrics: FileMetrics {
                lines: if source.is_empty() {
                    0
                } else {
                    u32_saturating(source.lines().count())
                },
                code_lines: 0,
                comment_lines: 0,
            },
        };
    };
    let root = tree.root_node();
    let metrics = support::file_metrics(root, source);
    FileReport {
        path,
        language: "java".to_owned(),
        issues: Vec::new(),
        metrics,
    }
}

/// Exact `CodeQL` query IDs emitted by [`analyze_github_quality`], in sorted order.
pub const GITHUB_QUALITY_RULE_IDS: &[&str] = &[
    "java/class-name-matches-super-class",
    "java/confusing-method-name",
    "java/confusing-method-signature",
    "java/constants-only-interface",
    "java/inefficient-string-constructor",
    "java/junit5-missing-nested-annotation",
    "java/label-in-switch",
    "java/misleading-indentation",
    "java/missing-space-in-concatenation",
    "java/non-explicit-control-and-whitespace-chars-in-literals",
    "java/string-buffer-char-init",
    "java/underscore-identifier",
    "java/unknown-javadoc-parameter",
    "java/unused-label",
    "java/whitespace-contradicts-precedence",
];

/// Runs independently registered GitHub Code Quality rules. The Java query
/// subset is syntax/scope-feasible and remains fail-closed on recovered trees.
#[must_use]
pub fn analyze_github_quality(source: &str) -> Vec<Issue> {
    let Some(tree) = context::parse(source) else {
        return Vec::new();
    };
    let root = tree.root_node();
    if root.has_error() {
        return Vec::new();
    }
    let lines = support::LineIndex::new(source);
    let issues = engine::github_quality_issues(root, source, &lines);
    debug_assert!(
        issues
            .iter()
            .all(|issue| GITHUB_QUALITY_RULE_IDS.contains(&issue.rule_key.as_str()))
    );
    issues
}

/// Parses source for callers that need the tolerant CST directly.
#[must_use]
pub fn parse(source: &str) -> Option<tree_sitter::Tree> {
    context::parse(source)
}

/// Builds semantic facts for one parsed source tree.
#[must_use]
pub fn semantic_index(source: &str) -> SemanticIndex {
    let Some(tree) = context::parse(source) else {
        return context::SemanticIndex::empty();
    };
    if tree.root_node().has_error() {
        return context::SemanticIndex::empty();
    }
    let lines = support::LineIndex::new(source);
    SemanticIndex::build(tree.root_node(), source, &lines)
}

/// Builds bounded flow summaries for every method with a body.
#[must_use]
pub fn method_flows(source: &str) -> Vec<MethodFlow> {
    let Some(tree) = context::parse(source) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }
    let lines = support::LineIndex::new(source);
    let root = tree.root_node();
    let semantics = SemanticIndex::build(root, source, &lines);
    engine::method_flows(root, source, &lines, &semantics)
}

#[cfg(test)]
mod tests {
    use super::{AnalyzerOptions, analyze, analyze_github_quality, method_flows, semantic_index};
    use std::path::PathBuf;

    #[test]
    fn do_while_block_repeats_the_body_before_retesting() {
        let flows = method_flows("class C { void f(int x) { do { x++; } while (x < 3); } }");
        let cfg = &flows[0].cfg;
        let body = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "expression_statement")
            .unwrap();
        let condition = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "condition")
            .unwrap();
        assert!(body.successors.contains(&condition.id));
        let mut repeated = cfg.clone();
        repeated.entry = condition.id;
        assert!(
            repeated.reachable().contains(&body.id),
            "true branch must repeat the body"
        );
    }

    #[test]
    fn empty_do_while_body_retests_its_condition() {
        let flows = method_flows("class C { void f(boolean ready) { do {} while (ready); } }");
        let cfg = &flows[0].cfg;
        let condition = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "condition")
            .unwrap();
        assert!(condition.successors.iter().any(|id| {
            let mut repeated = cfg.clone();
            repeated.entry = *id;
            repeated.reachable().contains(&condition.id)
        }));
        assert!(cfg.reachable().contains(&condition.id));
    }

    #[test]
    fn do_while_reenters_nested_loops_and_labelled_bodies() {
        for source in [
            "class C { void f(int x, boolean a, boolean b) { do { do { x++; } while (a); } while (b); } }",
            "class C { void f(int x, boolean ready) { do { label: { x++; } } while (ready); } }",
        ] {
            let flows = method_flows(source);
            let mut repeated = flows[0].cfg.clone();
            repeated.entry = repeated
                .nodes
                .iter()
                .find(|node| node.kind == "condition")
                .unwrap()
                .id;
            let body = repeated
                .nodes
                .iter()
                .find(|node| node.kind == "expression_statement")
                .unwrap();
            assert!(repeated.reachable().contains(&body.id), "{source}");
        }
    }

    #[test]
    fn for_continue_executes_every_update_in_order() {
        let flows = method_flows(
            "class C { void f() { for (int i = 0, j = 0; i < 3; i++, j++) { continue; } } }",
        );
        let cfg = &flows[0].cfg;
        let updates: Vec<_> = cfg
            .nodes
            .iter()
            .filter(|node| node.kind == "update_expression")
            .collect();
        assert_eq!(updates.len(), 2, "both loop updates must be modeled");
        let jump = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "continue")
            .unwrap();
        let condition = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "condition")
            .unwrap();
        assert_eq!(jump.successors, vec![updates[0].id]);
        assert_eq!(updates[0].successors, vec![updates[1].id]);
        assert_eq!(updates[1].successors, vec![condition.id]);
    }

    #[test]
    fn conditionless_for_does_not_fabricate_an_exit() {
        let flows = method_flows("class C { void f() { for (;;) { continue; } } }");
        let cfg = &flows[0].cfg;
        let condition = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "condition")
            .unwrap();
        assert!(
            !condition
                .successors
                .iter()
                .any(|id| cfg.nodes[*id].kind == "loop_join")
        );
    }

    #[test]
    fn labelled_continue_targets_the_named_loop_update() {
        let flows = method_flows(
            "class C { void f(boolean ready) { outer: for (int i = 0; i < 3; i++) { while (ready) { continue outer; } } } }",
        );
        let cfg = &flows[0].cfg;
        let update = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "update_expression")
            .unwrap();
        let jump = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "continue")
            .unwrap();
        assert_eq!(jump.successors, vec![update.id]);
    }

    #[test]
    fn unlabelled_break_skips_labelled_block_targets() {
        let flows = method_flows(
            "class C { void f(boolean ready) { while (ready) { label: { break; } } } }",
        );
        let cfg = &flows[0].cfg;
        let after_loop = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "loop_join")
            .unwrap();
        let jump = cfg.nodes.iter().find(|node| node.kind == "break").unwrap();
        assert_eq!(jump.successors, vec![after_loop.id]);
    }

    #[test]
    fn for_executes_every_initializer_in_order() {
        let flows =
            method_flows("class C { void f(int i, int j) { for (i = 0, j = 0; i < 3; i++) {} } }");
        let cfg = &flows[0].cfg;
        let init: Vec<_> = cfg
            .nodes
            .iter()
            .filter(|node| node.kind == "assignment_expression")
            .collect();
        assert_eq!(init.len(), 2);
        let condition = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "condition")
            .unwrap();
        assert_eq!(cfg.nodes[cfg.entry].successors, vec![init[0].id]);
        assert_eq!(init[0].successors, vec![init[1].id]);
        assert_eq!(init[1].successors, vec![condition.id]);
    }

    #[test]
    fn unreachable_loop_updates_do_not_contribute_dataflow_facts() {
        let flows = method_flows(
            "class C { int f(int n) { int x = 0; for (; x < n; x++) { break; } return x; } }",
        );
        let flow = &flows[0];
        let cfg = &flow.cfg;
        let update = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "update_expression")
            .unwrap();
        assert!(!cfg.reachable().contains(&update.id));
        assert!(flow.facts.reaching_out[update.id].is_empty());
        assert!(flow.facts.live_in[update.id].is_empty());
        let returned = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "return_statement")
            .unwrap();
        assert!(
            !flow.facts.reaching_in[returned.id]
                .iter()
                .any(|definition| definition.site == update.id)
        );
    }

    #[test]
    fn valid_java_reports_metrics_and_no_placeholder_findings() {
        let source = "package demo;\n// comment\nclass A { int x; }\n";
        let report = analyze(PathBuf::from("A.java"), source, &AnalyzerOptions::default());
        assert_eq!(report.language, "java");
        assert_eq!(report.metrics.lines, 3);
        assert_eq!(report.metrics.comment_lines, 1);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn malformed_java_fails_closed_but_keeps_metrics() {
        let source = "class A { void f( { int x = ;";
        let report = analyze(PathBuf::from("A.java"), source, &AnalyzerOptions::default());
        assert!(report.issues.is_empty());
        assert_eq!(report.metrics.lines, 1);
    }

    #[test]
    fn github_quality_rules_are_deterministic_and_fail_closed() {
        assert!(analyze_github_quality("class A {}").is_empty());
        assert!(analyze_github_quality("class A { void f( {").is_empty());
        assert_eq!(
            analyze_github_quality("class A {}"),
            analyze_github_quality("class A {}")
        );
    }

    #[test]
    fn github_quality_reports_all_feasible_query_families() {
        let source = concat!(
            r#"
import org.junit.jupiter.api.Test;
class Same extends Same {}
class Names {
    /** @param wrong stale */ void toUri() {}
    void toURI() {}
    void overload(String value) {}
    void overload(Object value) {}
    void build(int x) {
        String s = "hello" + "world";
        new String("x"); new StringBuffer('x');
        int _ = 1;
        if (x > 0)
            foo();
            bar();
        unused: while (x > 0) { break; }
        int n = x + x>>1;
        String invisible = "a"#,
            "\u{200B}",
            r#"b";
        switch (x) { case 1: inner: break; }
    }
}
interface Constants { int VALUE = 1; }
class Uses implements Constants {}
class Outer { class Inner { @Test void test() {} } }
"#,
        );
        let keys: std::collections::BTreeSet<_> = analyze_github_quality(source)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect();
        for key in [
            "java/class-name-matches-super-class",
            "java/confusing-method-name",
            "java/confusing-method-signature",
            "java/constants-only-interface",
            "java/inefficient-string-constructor",
            "java/misleading-indentation",
            "java/missing-space-in-concatenation",
            "java/label-in-switch",
            "java/non-explicit-control-and-whitespace-chars-in-literals",
            "java/unknown-javadoc-parameter",
            "java/underscore-identifier",
            "java/unused-label",
            "java/string-buffer-char-init",
            "java/junit5-missing-nested-annotation",
            "java/whitespace-contradicts-precedence",
        ] {
            assert!(keys.contains(key), "missing {key}: {keys:?}");
        }
        assert!(analyze_github_quality("class Clean { int value; }").is_empty());
    }

    #[test]
    fn github_quality_rejects_reviewed_false_positives() {
        let source = r#"
class A { void f(Object value) {} }
class B { void f(String value) {} }
abstract class ConstructedConstants {
    static final int VALUE = 1;
    ConstructedConstants() {}
}
class UsesConstructedConstants extends ConstructedConstants {}
class Test {}
class Outer {
    @Test void customAnnotation() {}
    class Inner {}
    void build(int a, int b, int c) {
        int conventional = a + b * c;
        new com.acme.String("x");
        new com.acme.StringBuilder('x');
    }
}
"#;
        let keys: std::collections::BTreeSet<_> = analyze_github_quality(source)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect();
        for key in [
            "java/confusing-method-signature",
            "java/inefficient-string-constructor",
            "java/string-buffer-char-init",
            "java/whitespace-contradicts-precedence",
            "java/junit5-missing-nested-annotation",
            "java/constants-only-interface",
        ] {
            assert!(!keys.contains(key), "unexpected {key}: {keys:?}");
        }
    }
    #[test]
    fn github_quality_uses_proven_argument_types_and_literal_offsets() {
        let source = r#"
class C {
    void f() {
        String text = "x";
        char ch = 'x';
        new String(text);
        new StringBuilder(ch);
        String joined = "Hello," + "world";
        String hidden = "a\u{200B}b";
    }
}
"#
        .replace(r"\u{200B}", "\u{200B}");
        let findings = analyze_github_quality(&source);
        assert_eq!(
            findings
                .iter()
                .filter(|issue| issue.rule_key == "java/inefficient-string-constructor")
                .count(),
            1
        );
        assert_eq!(
            findings
                .iter()
                .filter(|issue| issue.rule_key == "java/string-buffer-char-init")
                .count(),
            1
        );
        let literal = findings
            .iter()
            .find(|issue| {
                issue.rule_key == "java/non-explicit-control-and-whitespace-chars-in-literals"
            })
            .expect("literal finding");
        assert!(literal.message.contains("index 2"));
        assert!(
            findings
                .iter()
                .any(|issue| issue.rule_key == "java/missing-space-in-concatenation")
        );
    }

    #[test]
    fn github_quality_covers_package_underscore_and_abstract_constant_supers() {
        let source = r"
package _.internal;
abstract class Constants { static final int VALUE = 1; }
class Uses extends Constants {}
interface OtherConstants { int OTHER = 2; }
class UsesMany implements Runnable, OtherConstants { public void run() {} }
class Values {
    void f() { java.util.function.IntUnaryOperator op = _ -> _; }
}
";
        let keys: std::collections::BTreeSet<_> = analyze_github_quality(source)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect();
        assert!(keys.contains("java/underscore-identifier"));
        assert!(keys.contains("java/constants-only-interface"));
    }

    #[test]
    fn public_semantic_and_flow_helpers_are_stable() {
        let source = "class A { int f(int x) { int y = x; return y; } }";
        let index = semantic_index(source);
        assert!(index.symbols.iter().any(|symbol| symbol.name == "f"));
        let flows = method_flows(source);
        assert_eq!(flows.len(), 1);
        assert!(flows[0].facts.iterations > 0);
    }
    #[test]
    fn advanced_semantics_keep_records_lambdas_and_nested_scopes_conservative() {
        let source = r#"
import java.util.List;
record Box<T>(T value) {
    String text() { return value.toString(); }
}
class Host {
    void use(List<String> values) {
        for (String item : values) { new String(item); }
        try (java.io.InputStream stream = open()) {
            stream.toString();
        }
        Runnable task = new Runnable() {
            String field;
            public void run() { field = "x"; }
        };
        values.stream().map(String::trim).forEach(item -> item.trim());
    }
}
"#;
        let index = semantic_index(source);
        assert!(index.symbols.iter().any(|symbol| {
            symbol.name == "Box" && matches!(&symbol.kind, super::SymbolKind::Type)
        }));
        assert!(index.symbols.iter().any(|symbol| symbol.name == "T"));
        assert!(index.symbols.iter().any(|symbol| symbol.name == "value"));
        assert!(index.symbols.iter().any(|symbol| symbol.name == "item"));
        assert!(index.symbols.iter().any(|symbol| symbol.name == "stream"));
        assert!(index.symbols.iter().any(|symbol| symbol.name == "field"));
        assert!(
            index
                .references
                .iter()
                .any(|reference| reference.name == "value" && reference.symbol.is_some())
        );
        assert!(
            index
                .references
                .iter()
                .any(|reference| reference.name == "item" && reference.symbol.is_some())
        );
    }

    #[test]
    fn github_quality_uses_qualified_junit_and_test_class_boundaries() {
        let source = "\
import org.junit.jupiter.api.RepeatedTest;
class Outer {
    class Inner {
        @RepeatedTest(2) void repeated() {}
    }
}
class Contest {
    void build() { String value = \"a\u{200B}b\"; }
}
interface First { void run(Object value); }
interface Second { void run(String value); }
";
        let findings = analyze_github_quality(source);
        assert_eq!(
            findings
                .iter()
                .filter(|issue| issue.rule_key == "java/junit5-missing-nested-annotation")
                .count(),
            1
        );
        assert_eq!(
            findings
                .iter()
                .filter(|issue| {
                    issue.rule_key == "java/non-explicit-control-and-whitespace-chars-in-literals"
                })
                .count(),
            1
        );
        assert_eq!(
            findings
                .iter()
                .filter(|issue| issue.rule_key == "java/confusing-method-signature")
                .count(),
            0
        );
    }

    #[test]
    fn jdk_constructor_lookup_is_lexical_for_type_parameters() {
        let source = "\
class Generic<String> {}
class Uses {
    void plain() { new String(\"value\"); }
    <String> void shadowed() { new String(\"value\"); }
}
";
        let findings = analyze_github_quality(source);
        let counts = findings.iter().fold(
            std::collections::BTreeMap::<&str, usize>::new(),
            |mut counts, issue| {
                *counts.entry(issue.rule_key.as_str()).or_default() += 1;
                counts
            },
        );
        assert_eq!(
            counts
                .get("java/inefficient-string-constructor")
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            counts
                .get("java/string-buffer-char-init")
                .copied()
                .unwrap_or(0),
            0
        );
        let issue = findings
            .iter()
            .find(|issue| issue.rule_key == "java/inefficient-string-constructor")
            .expect("plain JDK String constructor should be reported");
        assert_eq!(issue.message, "Inefficient new String(String) constructor.");
        assert_eq!(issue.range.start.line, 3);
    }

    #[test]
    fn compact_constructor_javadoc_uses_record_components() {
        let source = "\
record Pair(int x, int y) {
    /**
     * @param x Valid record component.
     * @param nope Unknown parameter.
     */
    Pair {
        this.x = x;
    }
}
";
        let findings = analyze_github_quality(source);
        let counts = findings.iter().fold(
            std::collections::BTreeMap::<&str, usize>::new(),
            |mut counts, issue| {
                *counts.entry(issue.rule_key.as_str()).or_default() += 1;
                counts
            },
        );
        assert_eq!(
            counts
                .get("java/unknown-javadoc-parameter")
                .copied()
                .unwrap_or(0),
            1
        );
        let issue = findings
            .iter()
            .find(|issue| issue.rule_key == "java/unknown-javadoc-parameter")
            .expect("unknown compact-constructor parameter should be reported");
        assert_eq!(
            issue.message,
            "@param tag \"nope\" does not match any actual parameter of constructor \"Pair()\"."
        );
        assert_eq!(issue.range.start.line, 4);
        assert_eq!(issue.range.start.column, 7);
    }

    #[test]
    fn malformed_semantic_public_helpers_do_not_expose_recovered_facts() {
        let source = "class Broken { void f( { String value = ;";
        assert!(semantic_index(source).symbols.is_empty());
        assert!(method_flows(source).is_empty());
    }
}
