use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of, simple_name};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::naming::type_members;
use crate::rules::structure::is_attributed;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6964 — missing JSON fields leave value-type inputs at
/// their defaults, so absent data becomes valid-looking zeros. Bound:
/// actions in classes carrying `[ApiController]`; nullable and
/// attributed parameters stay exempt.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if !has_any_attribute(class_declaration, source, &["ApiController"]) {
            continue;
        }
        for action in type_members(class_declaration)
            .into_iter()
            .filter(|member| member.kind() == "method_declaration")
        {
            if !MUTATION_HTTP_VERBS
                .iter()
                .any(|verb| has_any_attribute(action, source, &[verb]))
            {
                continue;
            }
            for parameter in parameters_of(action) {
                let is_value_type =
                    parameter
                        .child_by_field_name("type")
                        .is_some_and(|type_node| {
                            let text = node_text(type_node, source);
                            !text.contains('?')
                                && matches!(
                                    simple_name(text),
                                    "int"
                                        | "long"
                                        | "short"
                                        | "byte"
                                        | "bool"
                                        | "decimal"
                                        | "double"
                                        | "float"
                                        | "Guid"
                                        | "DateTime"
                                )
                        });
                if is_value_type && !is_attributed(parameter, source) {
                    issues.push(issue(
                        language,
                        "S6964",
                        "Make this value-type input nullable or validate presence to prevent under-posting.",
                        range_of(parameter, source),
                    ));
                }
            }
        }
    }
    issues
}

/// HTTP-mutation verbs under which model binding under-posts.
const MUTATION_HTTP_VERBS: [&str; 3] = ["HttpPost", "HttpPut", "HttpPatch"];
