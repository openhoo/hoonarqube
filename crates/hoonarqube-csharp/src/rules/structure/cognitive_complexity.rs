use super::support::CALLABLE_BODY_OWNER_KINDS;
use super::support::binary_operator;
use super::support::body_of;
use super::support::is_else_alternative;
use super::support::name_anchor;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3776 — cognitive complexity stays within the thresholds;
/// accessors use the smaller `propertyThreshold`.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for function in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        if is_error_tainted(function) {
            continue;
        }
        let Some(body) = body_of(function) else {
            continue;
        };
        let threshold = if function.kind() == "accessor_declaration" {
            options.maximum_accessor_complexity_threshold
        } else {
            options.maximum_cognitive_complexity_threshold
        };
        let score = cognitive_complexity(body, 0, source, None);
        if score > threshold {
            issues.push(issue(
                language,
                "S3776",
                format!(
                    "Refactor this method to reduce its Cognitive Complexity from {score} to the {threshold} allowed."
                ),
                range_of(name_anchor(function), source),
            ));
        }
    }
    issues
}

/// Simplified S3776 cognitive score: structural keywords weigh one plus
/// their nesting depth, `else if` links continue at the enclosing level,
/// each consecutive run of identical boolean operators weighs one, and
/// jumps weigh one each.
fn cognitive_complexity(
    node: Node<'_>,
    nesting: u32,
    source: &str,
    logic_chain: Option<&str>,
) -> u32 {
    let mut score = 0_u32;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if is_structural_kind(kind) {
            let else_if_link = kind == "if_statement" && is_else_alternative(child);
            score += structural_score(child, nesting, source, else_if_link);
        } else {
            score += non_structural_score(child, nesting, source, logic_chain);
        }
    }
    score
}

fn is_structural_kind(kind: &str) -> bool {
    matches!(
        kind,
        "if_statement"
            | "for_statement"
            | "foreach_statement"
            | "while_statement"
            | "do_statement"
            | "switch_statement"
            | "catch_clause"
            | "conditional_expression"
    )
}

/// An `else if` link continues the enclosing nesting level instead of
/// opening a deeper one; genuinely nested branches still escalate.
fn structural_score(child: Node<'_>, nesting: u32, source: &str, else_if_link: bool) -> u32 {
    let increment = if else_if_link { 1 } else { 1 + nesting };
    let child_nesting = if else_if_link { nesting } else { nesting + 1 };
    increment + cognitive_complexity(child, child_nesting, source, None)
}

/// Boolean operators charge once per consecutive identical sequence. Nested
/// callable bodies reset that chain before their contents are traversed.
fn non_structural_score<'a>(
    child: Node<'_>,
    nesting: u32,
    source: &'a str,
    logic_chain: Option<&'a str>,
) -> u32 {
    let kind = child.kind();
    let mut increment = u32::from(matches!(
        kind,
        "case" | "goto_statement" | "break_statement" | "continue_statement"
    ));
    let mut next_chain = logic_chain;
    if kind == "binary_expression" {
        let operator = binary_operator(child, source);
        if matches!(operator, "&&" | "||") && logic_chain != Some(operator) {
            increment += 1;
            next_chain = Some(operator);
        }
    }
    if matches!(kind, "lambda_expression" | "anonymous_method_expression") {
        next_chain = None;
    }
    increment + cognitive_complexity(child, nesting, source, next_chain)
}

#[cfg(test)]
mod tests {
    use crate::AnalyzerOptions;
    use crate::tests::{analyze_options, with_key};

    fn options_with_threshold(threshold: u32) -> AnalyzerOptions {
        AnalyzerOptions {
            maximum_cognitive_complexity_threshold: threshold,
            ..Default::default()
        }
    }

    #[test]
    fn s3776_counts_else_if_chains_at_the_enclosing_nesting_level() {
        let chained = "class A\n{\n    void M(bool a, bool b)\n    {\n        if (a)\n        {\n            Keep();\n        }\n        else if (b)\n        {\n            Keep();\n        }\n        else\n        {\n            Keep();\n        }\n    }\n}\n";
        // Both links stay flat: one increment each instead of 1 + 2.
        assert!(
            with_key(
                &analyze_options(chained, &options_with_threshold(2)),
                "csharpsquid:S3776"
            )
            .is_empty()
        );

        let report = analyze_options(chained, &options_with_threshold(1));
        let flagged = with_key(&report, "csharpsquid:S3776");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Refactor this method to reduce its Cognitive Complexity from 2 to the 1 allowed."
        );
    }

    #[test]
    fn s3776_keeps_genuinely_nested_ifs_escalating() {
        let nested = "class A\n{\n    void M(bool a, bool b)\n    {\n        if (a)\n        {\n            if (b)\n            {\n                Keep();\n            }\n        }\n    }\n}\n";
        assert!(
            with_key(
                &analyze_options(nested, &options_with_threshold(3)),
                "csharpsquid:S3776"
            )
            .is_empty()
        );

        let report = analyze_options(nested, &options_with_threshold(2));
        let flagged = with_key(&report, "csharpsquid:S3776");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Refactor this method to reduce its Cognitive Complexity from 3 to the 2 allowed."
        );
    }

    #[test]
    fn s3776_charges_boolean_operators_once_per_identical_sequence() {
        let mixed = "class A\n{\n    void M(bool a, bool b, bool c)\n    {\n        var x = a && b && c;\n        var y = a && b || c;\n        var z = (a && b) && c;\n    }\n}\n";
        // One `&&` run, an `&&`-to-`||` switch, and one parenthesized run:
        // three sequences total, so the score is 4 rather than 6.
        assert!(
            with_key(
                &analyze_options(mixed, &options_with_threshold(4)),
                "csharpsquid:S3776"
            )
            .is_empty()
        );

        let report = analyze_options(mixed, &options_with_threshold(3));
        let flagged = with_key(&report, "csharpsquid:S3776");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Refactor this method to reduce its Cognitive Complexity from 4 to the 3 allowed."
        );
    }

    #[test]
    fn s3776_restarts_boolean_sequences_across_statements() {
        let spread = "class A\n{\n    void M(bool a, bool b, bool c, bool d)\n    {\n        var first = a && b;\n        Log(first);\n        var second = c && d;\n    }\n}\n";
        // Separate statements never share a sequence, so the score is 2.
        assert!(
            with_key(
                &analyze_options(spread, &options_with_threshold(2)),
                "csharpsquid:S3776"
            )
            .is_empty()
        );

        let report = analyze_options(spread, &options_with_threshold(1));
        let flagged = with_key(&report, "csharpsquid:S3776");
        assert_eq!(
            flagged[0].message,
            "Refactor this method to reduce its Cognitive Complexity from 2 to the 1 allowed."
        );
    }
}
