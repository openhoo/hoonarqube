use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3415 — expected values come first in paired assertions.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        if !PAIRED_ASSERT_METHODS.contains(&callee_name(call, source).unwrap_or("")) {
            continue;
        }
        let arguments = invocation_arguments(call);
        if arguments.len() < 2 {
            continue;
        }
        let first = argument_expression(arguments[0]);
        let second = argument_expression(arguments[1]);
        if first.kind() == "identifier" && is_expectation_literal(second) {
            issues.push(issue(
                language,
                "S3415",
                "Put the expected value first in this assertion.",
                range_of(call),
            ));
        }
    }
    issues
}

/// MSTest-style assertion entry points carrying expected/actual pairs.
const PAIRED_ASSERT_METHODS: [&str; 4] = ["AreEqual", "AreNotEqual", "AreSame", "AreNotSame"];

/// Literal kinds that read as hard-coded expectations.
fn is_expectation_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "character_literal"
            | "boolean_literal"
            | "verbatim_string_literal"
    )
}
