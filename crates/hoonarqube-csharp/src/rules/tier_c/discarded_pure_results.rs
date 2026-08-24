use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, first_named_child, invocation_function};
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(|statement| first_named_child(statement))
        .filter(|expression| {
            expression.kind() == "invocation_expression" && is_pure_static_call(*expression, source)
        })
        .map(|expression| {
            issue(
                language,
                "S2201",
                "The result of this side-effect-free call is unused; remove the call or use its value.",
                range_of(expression),
            )
        })
        .collect()
}

/// csharpsquid:S2201 — discarded results of side-effect-free static calls.
/// Subset: a curated pure-API owner/method table (`Math`, `string`,
/// `DateTime`) called as a bare statement; user-declared pure functions and
/// discard-pattern assignments stay uncovered.
const PURE_STATIC_APIS: &[(&str, &[&str])] = &[
    (
        "Math",
        &[
            "Abs",
            "BigMul",
            "Ceiling",
            "Clamp",
            "Exp",
            "Floor",
            "IEEERemainder",
            "Log",
            "Log10",
            "Log2",
            "Max",
            "MaxMagnitude",
            "Min",
            "MinMagnitude",
            "Pow",
            "Round",
            "Sign",
            "Sqrt",
            "Truncate",
        ],
    ),
    (
        "string",
        &[
            "Compare",
            "CompareOrdinal",
            "IsNullOrEmpty",
            "IsNullOrWhiteSpace",
        ],
    ),
    ("DateTime", &["Compare", "DaysInMonth", "IsLeapYear"]),
];

/// Whether the call is a listed pure static API invoked through its owner.
fn is_pure_static_call(call: Node<'_>, source: &str) -> bool {
    let Some(function) = invocation_function(call) else {
        return false;
    };
    if function.kind() != "member_access_expression" {
        return false;
    }
    PURE_STATIC_APIS.iter().any(|(owner, methods)| {
        methods.contains(&callee_name(call, source).unwrap_or(""))
            && first_named_child(function)
                .is_some_and(|receiver| node_text(receiver, source).trim().ends_with(owner))
    })
}
