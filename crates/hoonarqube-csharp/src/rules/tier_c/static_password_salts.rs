use super::support::is_static_literal;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::{callee_name, creation_type_text, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    salted_hash_candidates(root, source)
        .into_iter()
        .filter(|candidate| invocation_arguments(*candidate).len() >= 2)
        .filter(|candidate| {
            invocation_arguments(*candidate)
                .into_iter()
                .skip(1)
                .any(|argument| is_static_literal(argument_expression(argument), source))
        })
        .map(|candidate| {
            issue(
                language,
                "S2053",
                "Use a random, unpredictable salt for this password hashing call.",
                range_of(candidate),
            )
        })
        .collect()
}

/// csharpsquid:S2053 — password hashing invoked with a compile-time constant
/// salt. Subset: `Rfc2898DeriveBytes` construction, `Rfc2898DeriveBytes.
/// Pbkdf2`, and any `HashPassword/Pbkdf2/PBKDF2` call whose second argument
/// is a static literal; salts computed at runtime stay untouched.
const SALT_TAKING_HASH_APIS: [&str; 3] = ["HashPassword", "Pbkdf2", "PBKDF2"];

fn salted_hash_candidates<'t>(root: Node<'t>, source: &str) -> Vec<Node<'t>> {
    let creations = collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| {
            simple_name(creation_type_text(*creation, source)) == "Rfc2898DeriveBytes"
        });
    let calls = collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| {
            callee_name(*call, source).is_some_and(|callee| SALT_TAKING_HASH_APIS.contains(&callee))
        });
    creations
        .chain(calls)
        .filter(|candidate| !is_error_tainted(*candidate))
        .collect()
}
