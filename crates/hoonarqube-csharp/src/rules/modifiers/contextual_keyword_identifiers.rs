use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2306 — `async` and `await` are contextual keywords, never
/// identifiers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for identifier in collect_kinds(root, &["identifier"]) {
        let text = node_text(identifier, source);
        if !matches!(text, "async" | "await") || !is_declaration_name(identifier) {
            continue;
        }
        issues.push(issue(
            language,
            "S2306",
            format!("Rename '{text}' to not use a contextual keyword as an identifier."),
            range_of(identifier, source),
        ));
    }
    issues
}

fn is_declaration_name(identifier: Node<'_>) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    if !matches!(
        parent.kind(),
        "accessor_declaration"
            | "catch_declaration"
            | "class_declaration"
            | "constructor_declaration"
            | "delegate_declaration"
            | "destructor_declaration"
            | "enum_declaration"
            | "enum_member_declaration"
            | "event_declaration"
            | "extern_alias_directive"
            | "file_scoped_namespace_declaration"
            | "from_clause"
            | "interface_declaration"
            | "local_function_statement"
            | "method_declaration"
            | "namespace_declaration"
            | "parameter"
            | "parameter_array"
            | "property_declaration"
            | "record_declaration"
            | "struct_declaration"
            | "tuple_element"
            | "tuple_pattern"
            | "type_parameter"
            | "using_directive"
            | "variable_declarator"
    ) {
        return false;
    }
    parent
        .child_by_field_name("name")
        .is_some_and(|name| name.id() == identifier.id())
}
