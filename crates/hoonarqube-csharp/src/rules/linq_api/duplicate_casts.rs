use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::declaration_contracts::enclosing_method;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3247 — repeated casts of one expression invite drift; cast
/// once and reuse the result.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut seen: std::collections::BTreeMap<(usize, String, String), u32> =
        std::collections::BTreeMap::new();
    let mut issues = Vec::new();
    for cast in collect_kinds(root, &["cast_expression"]) {
        if is_error_tainted(cast) {
            continue;
        }
        let Some((target_type, operand)) = cast_fields(cast, source) else {
            continue;
        };
        let scope = enclosing_method(cast).map_or(0, |method| method.id());
        let key = (scope, target_type, operand);
        let count = seen.entry(key).or_insert(0);
        *count += 1;
        if *count > 1 {
            issues.push(issue(
                language,
                "S3247",
                "Cast this expression once and store the result.",
                range_of(cast),
            ));
        }
    }
    issues
}

/// Cast type and trimmed operand text of a `(T) x` expression.
fn cast_fields(cast: Node<'_>, source: &str) -> Option<(String, String)> {
    let target_type = cast
        .child_by_field_name("type")
        .map(|type_node| node_text(type_node, source).to_string())?;
    let operand = cast
        .child_by_field_name("value")
        .map(|value| node_text(value, source).trim().to_string())?;
    Some((target_type, operand))
}
