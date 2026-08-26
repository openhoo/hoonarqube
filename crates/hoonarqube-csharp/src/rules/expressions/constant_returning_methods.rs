use super::support::block_statements;
use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3400 — methods whose whole body returns one literal. Entry
/// points and inherited contracts stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let name = method
            .child_by_field_name("name")
            .map_or("", |name| node_text(name, source));
        let modifiers = modifiers_of(method, source);
        if name == "Main"
            || ["abstract", "virtual", "override", "partial", "extern"]
                .iter()
                .any(|modifier| has_modifier(&modifiers, modifier))
        {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let statements = block_statements(body);
        let constant_return = match statements.as_slice() {
            [only] if only.kind() == "return_statement" => {
                first_named_child(*only).is_some_and(|value| LITERAL_KINDS.contains(&value.kind()))
            }
            _ => false,
        };
        if constant_return {
            issues.push(issue(
                language,
                "S3400",
                "Remove this method and declare a constant for its value instead.",
                range_of(method, source),
            ));
        }
    }
    issues
}

/// Literal node kinds accepted as constant returns.
const LITERAL_KINDS: [&str; 6] = [
    "integer_literal",
    "real_literal",
    "string_literal",
    "character_literal",
    "boolean_literal",
    "null_literal",
];
