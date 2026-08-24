use super::support::typed_variables;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, expression_name, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3172 — delegate subtraction hides removed handlers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let delegates = declared_delegate_names(root, source);
    let variables = typed_variables(root, source);
    let mut issues = Vec::new();
    for binary in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(binary) || operator_of(binary) != Some("-") {
            continue;
        }
        let Some((left, right)) = binary_operands(binary) else {
            continue;
        };
        if left.kind() != "identifier" || expression_name(right, source).is_none() {
            continue;
        }
        let name = node_text(left, source);
        let delegate_typed = variables
            .iter()
            .filter(|(variable, _)| *variable == name)
            .any(|(_, type_name)| is_delegate_type_name(Some(type_name), &delegates));
        if delegate_typed {
            issues.push(issue(
                language,
                "S3172",
                "Subtracting delegates silently removes handlers; unsubscribe with '-=' instead.",
                range_of(binary),
            ));
        }
    }
    issues
}

/// Delegate type names declared in the file.
fn declared_delegate_names<'a>(
    root: Node<'a>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
    collect_kinds(root, &["delegate_declaration"])
        .into_iter()
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect()
}

/// Whether a declared type spells a delegate: in-file delegates or common
/// handler suffixes.
fn is_delegate_type_name(
    type_name: Option<&str>,
    delegates: &std::collections::HashSet<&str>,
) -> bool {
    type_name.is_some_and(|name| {
        delegates.contains(name)
            || name.ends_with("Delegate")
            || name.ends_with("Handler")
            || name.ends_with("Callback")
            || name.ends_with("EventHandler")
    })
}
