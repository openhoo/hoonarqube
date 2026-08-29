use crate::CsLanguage;
use crate::cst::{collect_kinds, direct_attributes, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4159 — an `[Export(typeof(I))]` part must actually
/// implement the exported contract `I`. Bound: same-file classes;
/// contracts declared elsewhere are assumed satisfied.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        for attribute in direct_attributes(class_declaration) {
            let Some(name) = attribute.child_by_field_name("name") else {
                continue;
            };
            let attribute_name = crate::cst::simple_name(node_text(name, source));
            if attribute_name
                .strip_suffix("Attribute")
                .unwrap_or(attribute_name)
                != "Export"
            {
                continue;
            }
            let contract = collect_kinds(attribute, &["typeof_expression"])
                .into_iter()
                .find_map(|expression| typeof_type_text(expression, source));
            let implemented = contract.as_ref().is_some_and(|contract| {
                base_type_texts(class_declaration, source)
                    .iter()
                    .any(|base| equivalent_type_identity(base, contract))
            });
            if let Some(contract) = contract
                && !implemented
            {
                issues.push(issue(
                    language,
                    "S4159",
                    format!(
                        "Implement '{contract}' on '{}' or remove this export attribute.",
                        node_text(name_anchor(class_declaration), source)
                    ),
                    range_of(attribute, source),
                ));
            }
        }
    }
    issues
}

fn typeof_type_text<'a>(expression: Node<'_>, source: &'a str) -> Option<&'a str> {
    expression
        .child_by_field_name("type")
        .or_else(|| {
            expression
                .children(&mut expression.walk())
                .find(tree_sitter::Node::is_named)
        })
        .map(|type_node| node_text(type_node, source))
}

fn base_type_texts<'a>(declaration: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let Some(base_list) = declaration
        .children(&mut declaration.walk())
        .find(|child| child.kind() == "base_list")
    else {
        return Vec::new();
    };
    base_list
        .children(&mut base_list.walk())
        .filter(tree_sitter::Node::is_named)
        .map(|base| node_text(base, source))
        .collect()
}

fn equivalent_type_identity(left: &str, right: &str) -> bool {
    fn normalized(text: &str) -> String {
        text.chars()
            .filter(|character| !character.is_whitespace() && *character != '@')
            .collect::<String>()
            .replace("global::", "")
    }
    fn unqualified_outer(text: &str) -> &str {
        let generic = text.find('<').unwrap_or(text.len());
        let outer = &text[..generic];
        let start = outer.rfind('.').map_or(0, |index| index + 1);
        &text[start..]
    }

    let left = normalized(left);
    let right = normalized(right);
    left == right || unqualified_outer(&left) == unqualified_outer(&right)
}
