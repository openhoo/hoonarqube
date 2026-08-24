use super::support::this_or_identifier_name;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_receiver, member_declarations_of_kind};
use crate::rules::logging::field_declarator_names;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2952 — `Dispose` methods disposing objects that are not
/// members of their class. Subset: `.Dispose()` calls inside any method
/// named `Dispose` whose receiver is a bare identifier or `this.Name`
/// access missing from the class's field inventory; inherited members and
/// other receiver shapes stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class in collect_kinds(root, &["class_declaration", "struct_declaration"]) {
        if is_error_tainted(class) {
            continue;
        }
        let fields: std::collections::HashSet<&str> = type_members(class)
            .into_iter()
            .filter(|member| member.kind() == "field_declaration")
            .flat_map(|field| field_declarator_names(field, source))
            .collect();
        for method in member_declarations_of_kind(class, "method_declaration") {
            if method
                .child_by_field_name("name")
                .is_none_or(|name| node_text(name, source) != "Dispose")
            {
                continue;
            }
            for call in collect_kinds(method, &["invocation_expression"]) {
                if is_error_tainted(call) || callee_name(call, source) != Some("Dispose") {
                    continue;
                }
                let Some(receiver) = invocation_receiver(call) else {
                    continue;
                };
                let Some(name) = this_or_identifier_name(receiver, source) else {
                    continue;
                };
                if !fields.contains(name) {
                    issues.push(issue(
                        language,
                        "S2952",
                        "Only members of this class should be disposed from its 'Dispose' method.",
                        range_of(call),
                    ));
                }
            }
        }
    }
    issues
}
