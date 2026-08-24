use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{callee_name, invocation_function};
use crate::rules::literals::declarator_initializer;
use crate::symbol_table::UsageSymbols;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3063 — builders nobody ever turns into output.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declarator in collect_kinds(root, &["variable_declarator"]) {
        if is_error_tainted(declarator) {
            continue;
        }
        let container = declarator
            .parent()
            .and_then(|declaration| declaration.parent());
        if matches!(container, Some(container) if matches!(container.kind(), "field_declaration" | "event_field_declaration"))
        {
            continue;
        }
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let builds_content = declarator_initializer(declarator, name).is_some_and(|initializer| {
            initializer
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "StringBuilder"
                })
        });
        if !builds_content {
            continue;
        }
        let uses: Vec<Node> = symbols
            .uses_of(node_text(name, source))
            .into_iter()
            .filter(|use_site| use_site.byte_range().start > declarator.byte_range().end)
            .collect();
        if uses.is_empty()
            || uses
                .iter()
                .any(|use_site| consumes_string_builder(*use_site, source))
        {
            continue;
        }
        issues.push(issue(
            language,
            "S3063",
            format!(
                "The content of StringBuilder '{}' is never consumed.",
                node_text(name, source)
            ),
            range_of(declarator),
        ));
    }
    issues
}

/// `StringBuilder` members that mutate instead of yielding content.
const STRING_BUILDER_MUTATIONS: [&str; 7] = [
    "Append",
    "AppendLine",
    "AppendFormat",
    "Insert",
    "Remove",
    "Clear",
    "Replace",
];

/// Whether a reference reads a builder's content instead of mutating it.
fn consumes_string_builder(reference: Node<'_>, source: &str) -> bool {
    let Some(parent) = reference.parent() else {
        return true;
    };
    let invocation = parent.parent().filter(|grandparent| {
        parent.kind() == "member_access_expression"
            && grandparent.kind() == "invocation_expression"
            && invocation_function(*grandparent)
                .is_some_and(|function| function.id() == parent.id())
    });
    if let Some(invocation) = invocation {
        return !callee_name(invocation, source)
            .is_some_and(|callee| STRING_BUILDER_MUTATIONS.contains(&callee));
    }
    matches!(
        parent.kind(),
        "argument" | "return_statement" | "element_access_expression"
    )
}
