use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{enclosing_type, member_declarations_of_kind};
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3926 — `[OptionalField]` members need an `[OnDeserialized]`
/// hook to repair data written by older versions.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) || !has_any_attribute(field, source, &["OptionalField"]) {
            continue;
        }
        let hooked = enclosing_type(field).is_some_and(|ty| {
            member_declarations_of_kind(ty, "method_declaration")
                .iter()
                .any(|method| has_any_attribute(*method, source, &["OnDeserialized"]))
        });
        if !hooked {
            issues.push(issue(
                language,
                "S3926",
                "Handle this '[OptionalField]' member in an '[OnDeserialized]' callback.",
                range_of(field, source),
            ));
        }
    }
    issues
}
