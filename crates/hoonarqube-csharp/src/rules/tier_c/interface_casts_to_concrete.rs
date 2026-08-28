use super::support::declared_type_names;
use super::support::local_type_declarations;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3215 — casts from a file-local interface variable to a
/// concrete class implementing it. Subset: identifier operands resolved via
/// the declaration table; `as` conversions and pattern matches stay out.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let types = declared_type_names(root, source);
    let interfaces: std::collections::HashSet<&str> = local_type_declarations(root)
        .into_iter()
        .filter(|declaration| declaration.kind() == "interface_declaration")
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect();
    let classes: std::collections::HashSet<&str> = collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect();
    collect_kinds(root, &["cast_expression"])
        .into_iter()
        .filter(|cast| !is_error_tainted(*cast))
        .filter_map(|cast| {
            let target = simple_name(node_text(cast.child_by_field_name("type")?, source));
            let value = cast.child_by_field_name("value")?;
            Some((cast, target, value))
        })
        .filter(|(_, target, value)| {
            value.kind() == "identifier"
                && classes.contains(*target)
                && types
                    .get(node_text(*value, source))
                    .is_some_and(|declared| {
                        let declared = simple_name(declared);
                        interfaces.contains(declared) && declared != *target
                    })
        })
        .map(|(cast, _, _)| {
            issue(
                language,
                "S3215",
                "Remove this cast and edit the interface to add the missing functionality.",
                range_of(cast, source),
            )
        })
        .collect()
}
