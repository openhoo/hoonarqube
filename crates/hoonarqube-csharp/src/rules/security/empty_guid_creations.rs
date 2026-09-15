use super::support::call_argument_nodes;
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4581 — `new Guid()` and `default` expressions whose target
/// type is `System.Guid` produce the all-zeros identity; only `Guid.NewGuid`
/// produces a real one.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        if simple_name(creation_type_text(creation, source)) == "Guid"
            && call_argument_nodes(creation).is_empty()
        {
            issues.push(guid_issue(language, range_of(creation, source)));
        }
    }
    for default in collect_kinds(root, &["default_expression"]) {
        if is_error_tainted(default) || in_parameter_default(default) {
            continue;
        }
        let targets_guid = match default.child_by_field_name("type") {
            Some(type_node) => is_plain_guid(node_text(type_node, source)),
            None => bare_default_targets_guid(default, source),
        };
        if targets_guid {
            issues.push(guid_issue(language, range_of(default, source)));
        }
    }
    issues
}

fn guid_issue(language: CsLanguage, range: hoonarqube_ir::Range) -> Issue {
    issue(
        language,
        "S4581",
        "Use 'Guid.NewGuid()' or 'Guid.Empty' or add arguments to this GUID instantiation.",
        range,
    )
}

/// The reference skips default values inside parameter lists: a parameter
/// default cannot be replaced by the non-constant `Guid.Empty`.
fn in_parameter_default(default: Node<'_>) -> bool {
    ancestors_of(default).any(|ancestor| ancestor.kind() == "parameter")
}

/// Whether a written type text is exactly `Guid`, possibly qualified.
/// `Guid?` defaults to null, not to the empty identity, so the nullable
/// annotation never matches.
fn is_plain_guid(type_text: &str) -> bool {
    !type_text.trim().ends_with('?') && simple_name(type_text) == "Guid"
}

/// Target type of a bare `default` through the in-file assignment flow:
/// declarator initializers (`Guid g = default;`) and plain `=` assignments
/// whose target declaration is visible in-file (`clientConnectionId =
/// default;` for an `out Guid` parameter). Arguments, returns, and
/// cross-file members need compiler type resolution and stay unreported.
fn bare_default_targets_guid(default: Node<'_>, source: &str) -> bool {
    let Some(parent) = default.parent() else {
        return false;
    };
    match parent.kind() {
        "variable_declarator" => parent
            .parent()
            .and_then(|declaration| declaration.child_by_field_name("type"))
            .is_some_and(|type_node| is_plain_guid(node_text(type_node, source))),
        "assignment_expression" => {
            let plain_assignment = parent
                .child_by_field_name("operator")
                .is_some_and(|operator| node_text(operator, source) == "=");
            let Some(target) = parent.child_by_field_name("left") else {
                return false;
            };
            plain_assignment
                && assigned_target_type(target, default, source)
                    .is_some_and(|type_node| is_plain_guid(node_text(type_node, source)))
        }
        _ => false,
    }
}

/// Declared type node of an assignment target, resolved nearest scope
/// outward: locals of enclosing blocks, parameters of enclosing callables
/// (the `out Guid` flow), then fields and properties of enclosing types.
fn assigned_target_type<'a>(
    target: Node<'a>,
    assignment: Node<'a>,
    source: &str,
) -> Option<Node<'a>> {
    let name = match target.kind() {
        "identifier" => node_text(target, source),
        "member_access_expression" => {
            let name = target.child_by_field_name("name")?;
            node_text(name, source)
        }
        _ => return None,
    };
    for scope in ancestors_of(assignment) {
        let declared = match scope.kind() {
            "block" => block_local_type(scope, name, source),
            "method_declaration"
            | "constructor_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "local_function_statement" => callable_parameter_type(scope, name, source),
            "declaration_list" => type_member_type(scope, name, source),
            _ => None,
        };
        if declared.is_some() {
            return declared;
        }
    }
    None
}

fn block_local_type<'a>(block: Node<'a>, name: &str, source: &str) -> Option<Node<'a>> {
    let mut cursor = block.walk();
    block
        .children(&mut cursor)
        .filter(|statement| statement.kind() == "local_declaration_statement")
        .find_map(|statement| variable_declaration_type(statement, name, source))
}

fn callable_parameter_type<'a>(callable: Node<'a>, name: &str, source: &str) -> Option<Node<'a>> {
    parameters_of(callable)
        .into_iter()
        .find(|parameter| {
            parameter
                .child_by_field_name("name")
                .is_some_and(|candidate| node_text(candidate, source) == name)
        })
        .and_then(|parameter| parameter.child_by_field_name("type"))
}

fn type_member_type<'a>(declaration_list: Node<'a>, name: &str, source: &str) -> Option<Node<'a>> {
    let mut cursor = declaration_list.walk();
    let members: Vec<Node<'a>> = declaration_list
        .children(&mut cursor)
        .filter(|member| matches!(member.kind(), "field_declaration" | "property_declaration"))
        .collect();
    members.into_iter().find_map(|member| match member.kind() {
        "property_declaration" => {
            let declared = member.child_by_field_name("name")?;
            (node_text(declared, source) == name)
                .then(|| member.child_by_field_name("type"))
                .flatten()
        }
        _ => variable_declaration_type(member, name, source),
    })
}

/// Type of a `variable_declaration` when one of its declarators declares
/// `name`.
fn variable_declaration_type<'a>(
    statement: Node<'a>,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let mut cursor = statement.walk();
    let declaration = statement
        .children(&mut cursor)
        .find(|child| child.kind() == "variable_declaration")?;
    let mut declarator_cursor = declaration.walk();
    let declares_name = declaration
        .children(&mut declarator_cursor)
        .filter(|declarator| declarator.kind() == "variable_declarator")
        .any(|declarator| {
            declarator
                .child_by_field_name("name")
                .is_some_and(|candidate| node_text(candidate, source) == name)
        });
    declares_name
        .then(|| declaration.child_by_field_name("type"))
        .flatten()
}
