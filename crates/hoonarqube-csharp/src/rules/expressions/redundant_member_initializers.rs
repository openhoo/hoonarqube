use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_from_byte_offsets, range_of};
use crate::rules::expressions::{binary_operands, expression_name, member_declarations_of_kind};
use crate::rules::literals::declarator_initializer;
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3604 — object initializers assigning a member to an equally
/// named variable (`new P { X = x }`).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let constructors = member_declarations_of_kind(type_node, "constructor_declaration");
        if constructors.is_empty() {
            continue;
        }
        for field in type_members(type_node)
            .into_iter()
            .filter(|member| member.kind() == "field_declaration")
        {
            for declarator in collect_kinds(field, &["variable_declarator"]) {
                let Some(name) = declarator.child_by_field_name("name") else {
                    continue;
                };
                let Some(initializer) = declarator_initializer(declarator, name) else {
                    continue;
                };
                let name_text = node_text(name, source);
                let initialized_by_all = constructors.iter().all(|constructor| {
                    constructor.child_by_field_name("body").is_some_and(|body| {
                        collect_kinds(body, &["assignment_expression"])
                            .into_iter()
                            .any(|assignment| {
                                binary_operands(assignment).is_some_and(|(left, _)| {
                                    expression_name(left, source) == Some(name_text)
                                })
                            })
                    })
                });
                if !initialized_by_all {
                    continue;
                }
                let mut cursor = declarator.walk();
                let range = declarator
                    .children(&mut cursor)
                    .find(|child| child.kind() == "=")
                    .map_or_else(
                        || range_of(initializer, source),
                        |equals| {
                            range_from_byte_offsets(
                                equals.start_byte(),
                                initializer.end_byte(),
                                source,
                            )
                        },
                    );
                issues.push(issue(
                    language,
                    "S3604",
                    "Remove the member initializer, all constructors set an initial value for the member.",
                    range,
                ));
            }
        }
    }
    issues
}
