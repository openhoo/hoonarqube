use super::support::type_parameter_list_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2326 — type parameters unused anywhere in their declaration
/// are dead weight; constraint references count as usage. Shadowing between
/// nested scopes is ignored.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    declarations.extend(collect_kinds(
        root,
        &["method_declaration", "delegate_declaration"],
    ));
    let mut issues = Vec::new();
    for declaration in declarations {
        let Some((list, _)) = type_parameter_list_of(declaration) else {
            continue;
        };
        let mut list_cursor = list.walk();
        for parameter in list
            .children(&mut list_cursor)
            .filter(|child| child.kind() == "type_parameter")
        {
            let name_node = parameter.child_by_field_name("name").unwrap_or(parameter);
            let name = node_text(name_node, source);
            if !is_type_parameter_used(declaration, list, name, source) {
                issues.push(issue(
                    language,
                    "S2326",
                    format!("'{name}' is not used in the class."),
                    range_of(name_node, source),
                ));
            }
        }
    }
    issues
}

/// Looks for a real use while pruning nested generic scopes that redeclare the
/// same name. Identifiers serving as declaration/member names do not count as
/// type references.
fn is_type_parameter_used(
    declaration: Node<'_>,
    parameter_list: Node<'_>,
    name: &str,
    source: &str,
) -> bool {
    let mut stack = vec![declaration];
    while let Some(node) = stack.pop() {
        if node == parameter_list {
            continue;
        }
        if node != declaration && declaration_shadows(node, name, source) {
            continue;
        }
        if node.kind() == "identifier" && node_text(node, source) == name && !is_name_field(node) {
            return true;
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    false
}

fn declaration_shadows(node: Node<'_>, name: &str, source: &str) -> bool {
    type_parameter_list_of(node).is_some_and(|(list, _)| {
        let mut cursor = list.walk();
        list.children(&mut cursor)
            .filter(|child| child.kind() == "type_parameter")
            .filter_map(|parameter| parameter.child_by_field_name("name"))
            .any(|parameter_name| node_text(parameter_name, source) == name)
    })
}

fn is_name_field(identifier: Node<'_>) -> bool {
    identifier
        .parent()
        .is_some_and(|parent| parent.child_by_field_name("name") == Some(identifier))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2326_does_not_treat_shadowed_nested_type_parameter_as_outer_use() {
        let report = analyze_default("class Outer<T>\n{\n    void M<T>(T value) { }\n}\n");
        let flagged = with_key(&report, "csharpsquid:S2326");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s2326_does_not_treat_member_name_as_type_parameter_use() {
        let report = analyze_default("class Container<T>\n{\n    int T;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S2326");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.column, 16);
    }

    #[test]
    fn s2326_counts_outer_type_use_inside_non_shadowing_nested_type() {
        let report = analyze_default(
            "class Outer<T>\n{\n    class Inner\n    {\n        T value;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2326").is_empty());
    }
}
