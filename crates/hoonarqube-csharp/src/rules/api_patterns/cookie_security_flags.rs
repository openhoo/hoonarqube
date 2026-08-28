use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use crate::rules::dataflow::callable_blocks;
use crate::rules::expressions::{expression_name, operator_of};
use crate::rules::literals::assignment_target_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2092 and csharpsquid:S3330 — session cookies without
/// `Secure` travel over plain HTTP, and cookies without `HttpOnly` are
/// readable from scripts. Bound: cookies created and configured inside
/// one member body, tracked by storage name.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for (creation, name) in cookie_creations(body, source) {
            if !cookie_sets_property_true(body, source, name, "Secure") {
                issues.push(issue(
                    language,
                    "S2092",
                    "Make sure creating this cookie without setting the 'Secure' property is safe here.",
                    range_of(creation, source),
                ));
            }
            if !cookie_sets_property_true(body, source, name, "HttpOnly") {
                issues.push(issue(
                    language,
                    "S3330",
                    "Make sure creating this cookie without the \"HttpOnly\" flag is safe.",
                    range_of(creation, source),
                ));
            }
        }
    }
    issues
}

/// `HttpCookie` creations paired with the local or property they are
/// stored in; unbound creations (`new HttpCookie(..)` as an argument)
/// are skipped.
fn cookie_creations<'t, 's>(body: Node<'t>, source: &'s str) -> Vec<(Node<'t>, &'s str)> {
    collect_kinds(body, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .map(|type_node| simple_name(node_text(type_node, source)))
                == Some("HttpCookie")
        })
        .filter_map(|creation| {
            let parent = creation.parent()?;
            let bound = match parent.kind() {
                "variable_declarator" => parent.child_by_field_name("name"),
                "assignment_expression" => parent.child_by_field_name("left"),
                _ => None,
            };
            let name = bound.and_then(|bound| assignment_target_name(bound, source))?;
            Some((creation, name))
        })
        .collect()
}

/// Whether the member sets `<name>.<property> = true` anywhere.
fn cookie_sets_property_true(body: Node<'_>, source: &str, name: &str, property: &str) -> bool {
    collect_kinds(body, &["assignment_expression"])
        .into_iter()
        .any(|assignment| {
            operator_of(assignment) == Some("=")
                && assignment.child_by_field_name("left").is_some_and(|left| {
                    left.kind() == "member_access_expression"
                        && expression_name(left, source) == Some(property)
                        && left.child_by_field_name("expression").is_some_and(|base| {
                            base.kind() == "identifier" && node_text(base, source) == name
                        })
                })
                && assignment
                    .child_by_field_name("right")
                    .is_some_and(|right| {
                        right.kind() == "boolean_literal" && node_text(right, source) == "true"
                    })
        })
}
