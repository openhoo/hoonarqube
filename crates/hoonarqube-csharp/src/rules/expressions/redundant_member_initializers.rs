use super::support::{enclosing_callable, field_declarators, local_identifier_type};
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
            for declarator in field_declarators(field) {
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
                            .filter(|assignment| {
                                enclosing_callable(*assignment)
                                    .is_some_and(|owner| owner.id() == constructor.id())
                            })
                            .any(|assignment| {
                                binary_operands(assignment).is_some_and(|(left, _)| {
                                    assigns_member(left, name_text, source)
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

fn assigns_member(target: Node<'_>, member_name: &str, source: &str) -> bool {
    match target.kind() {
        "identifier" => {
            expression_name(target, source) == Some(member_name)
                && local_identifier_type(target, source).is_none()
        }
        "member_access_expression" => {
            expression_name(target, source) == Some(member_name)
                && node_text(target, source)
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .eq(format!("this.{member_name}").chars())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3604_flags_initializer_set_by_every_constructor() {
        let report = analyze_default(
            "class C { int value = 1; C() { value = 2; } C(int other) { this.value = other; } }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3604").len(), 1);
    }

    #[test]
    fn s3604_ignores_assignments_inside_nested_callables() {
        let report = analyze_default(
            "class C { int value = 1; C() { System.Action set = () => value = 2; } }",
        );
        assert!(with_key(&report, "csharpsquid:S3604").is_empty());
    }

    #[test]
    fn s3604_ignores_assignments_to_locals_and_foreign_objects() {
        let report = analyze_default(
            "class C { int value = 1; C(C other) { int value = 0; value = 2; other.value = 3; } }",
        );
        assert!(with_key(&report, "csharpsquid:S3604").is_empty());
    }
}
