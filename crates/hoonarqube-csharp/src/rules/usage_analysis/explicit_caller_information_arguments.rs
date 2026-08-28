use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3236 — caller-information arguments are supplied by the
/// compiler and must not be spelled out at call sites.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let parameters = parameters_of(method);
        let supplied_by_compiler = parameters
            .iter()
            .filter(|parameter| {
                has_any_attribute(**parameter, source, &CALLER_INFORMATION_ATTRIBUTES)
            })
            .count();
        if supplied_by_compiler == 0 || supplied_by_compiler >= parameters.len() {
            continue;
        }
        let expected = parameters.len() - supplied_by_compiler;
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        for invocation in collect_kinds(root, &["invocation_expression"]) {
            if callee_name(invocation, source) != Some(node_text(name, source)) {
                continue;
            }
            let arguments = invocation_arguments(invocation);
            if arguments.len() <= expected {
                continue;
            }
            issues.extend(arguments[expected..].iter().map(|argument| {
                issue(
                    language,
                    "S3236",
                    "Remove this argument from the method call; it hides the caller information.",
                    range_of(*argument, source),
                )
            }));
        }
    }
    issues
}

/// Attributes whose arguments the compiler fills in automatically.
const CALLER_INFORMATION_ATTRIBUTES: [&str; 3] = [
    "CallerFilePath",
    "CallerLineNumber",
    "CallerArgumentExpression",
];
