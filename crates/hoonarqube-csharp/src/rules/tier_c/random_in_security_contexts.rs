use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| simple_name(creation_type_text(*creation, source)).ends_with("Random"))
        .filter(|creation| security_context_hit(*creation, source))
        .map(|creation| {
            issue(
                language,
                "S2245",
                "Use a cryptographically secure random number generator for this security-sensitive value.",
                range_of(creation),
            )
        })
        .collect()
}

/// csharpsquid:S2245 — `System.Random` created inside a security-named
/// context (token/password/secret/nonce/salt/csrf naming heuristic over the
/// enclosing member, type, or assigned variable).
const SECURITY_CONTEXT_WORDS: [&str; 6] =
    ["token", "password", "passwd", "secret", "nonce", "csrf"];

/// Whether a candidate context name carries a security word.
fn security_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECURITY_CONTEXT_WORDS
        .iter()
        .any(|word| lower.contains(word))
}

/// Any enclosing declaration or assigned-variable name carrying a security
/// word around the given expression.
fn security_context_hit(expression: Node<'_>, source: &str) -> bool {
    let mut context_names: Vec<&str> = Vec::new();
    let mut ancestor = expression.parent();
    while let Some(current) = ancestor {
        if matches!(
            current.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "interface_declaration"
                | "variable_declarator"
        ) && let Some(name) = current.child_by_field_name("name")
        {
            context_names.push(node_text(name, source));
        }
        ancestor = current.parent();
    }
    context_names.iter().any(|name| security_named(name))
}
