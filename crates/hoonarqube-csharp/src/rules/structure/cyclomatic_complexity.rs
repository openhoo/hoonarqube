use super::support::CALLABLE_BODY_OWNER_KINDS;
use super::support::binary_operator;
use super::support::body_of;
use super::support::name_anchor;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, walk_all};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1541 — a function's cyclomatic complexity stays within the
/// threshold.
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
        let complexity = 1 + cyclomatic_decisions(body, source);
        if complexity > options.maximum_function_complexity_threshold {
            issues.push(issue(
                language,
                "S1541",
                format!(
                    "Reduce this function's cyclomatic complexity from {complexity} to at most {}.",
                    options.maximum_function_complexity_threshold
                ),
                range_of(name_anchor(function), source),
            ));
        }
    }
    issues
}

/// Decision points of the S1541 cyclomatic walk: branching statements,
/// case labels, catches, ternaries, null-coalescing, and short-circuiting
/// operators. Nested local functions count toward their enclosing member.
fn cyclomatic_decisions(body: Node<'_>, source: &str) -> u32 {
    let mut decisions = 0_u32;
    walk_all(body, &mut |node| match node.kind() {
        "if_statement"
        | "for_statement"
        | "foreach_statement"
        | "while_statement"
        | "do_statement"
        | "catch_clause"
        | "conditional_expression"
        | "coalescing_expression"
        | "case" => decisions += 1,
        "binary_expression" => {
            if matches!(binary_operator(node, source), "&&" | "||" | "??") {
                decisions += 1;
            }
        }
        _ => {}
    });
    decisions
}
