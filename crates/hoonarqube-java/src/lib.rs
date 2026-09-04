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
/// findings. Syntax errors fail closed: recovered trees are indexed only by
/// internal tests/future rules and never produce fabricated issues.
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
    let line_index = support::LineIndex::new(source);
    let metrics = support::file_metrics(root, source);
    let _semantic_index = context::SemanticIndex::build(root, source, &line_index);
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
    let lines = support::LineIndex::new(source);
    SemanticIndex::build(tree.root_node(), source, &lines)
}

/// Builds bounded flow summaries for every method with a body.
#[must_use]
pub fn method_flows(source: &str) -> Vec<MethodFlow> {
    let Some(tree) = context::parse(source) else {
        return Vec::new();
    };
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
}
