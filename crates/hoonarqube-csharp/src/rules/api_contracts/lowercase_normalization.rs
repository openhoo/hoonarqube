use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4040 — normalization belongs in uppercase; lowercased
/// strings compare and hash differently across cultures.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| TO_LOWER_METHODS.contains(&callee_name(*call, source).unwrap_or("")))
        .map(|call| {
            issue(
                language,
                "S4040",
                "Use 'ToUpperInvariant' to normalize this string.",
                range_of(call),
            )
        })
        .collect()
}

/// Methods that normalize text and must not fold case downwards.
const TO_LOWER_METHODS: [&str; 2] = ["ToLower", "ToLowerInvariant"];
