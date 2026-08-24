use super::support::CALLABLE_BODY_OWNER_KINDS;
use super::support::binary_operator;
use super::support::body_of;
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
        let score = cognitive_complexity(body, 0, source);
        if score > threshold {
            issues.push(issue(
                language,
                "S3776",
                format!(
                    "Reduce this function's cognitive complexity from {score} to at most {threshold}."
                ),
                range_of(name_anchor(function)),
            ));
        }
    }
    issues
}

/// Simplified S3776 cognitive score: structural keywords weigh one plus
/// their nesting depth, boolean operators and jumps weigh one each.
fn cognitive_complexity(node: Node<'_>, nesting: u32, source: &str) -> u32 {
    let mut score = 0_u32;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if matches!(
            kind,
            "if_statement"
                | "for_statement"
                | "foreach_statement"
                | "while_statement"
                | "do_statement"
                | "switch_statement"
                | "catch_clause"
                | "conditional_expression"
        ) {
            score += 1 + nesting;
            score += cognitive_complexity(child, nesting + 1, source);
        } else {
            match kind {
                "case" | "goto_statement" | "break_statement" | "continue_statement" => {
                    score += 1;
                }
                "binary_expression" => {
                    if matches!(binary_operator(child, source), "&&" | "||") {
                        score += 1;
                    }
                }
                _ => {}
            }
            score += cognitive_complexity(child, nesting, source);
        }
    }
    score
}
