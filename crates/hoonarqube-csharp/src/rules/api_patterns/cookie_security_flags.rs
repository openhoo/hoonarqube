use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of, simple_name};
use crate::rules::dataflow::{callable_blocks, walk_owned};
use crate::rules::expressions::{expression_name, operator_of};
use crate::rules::literals::assignment_target_name;
use hoonarqube_ir::Issue;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Default)]
struct CookieFlags {
    secure: bool,
    http_only: bool,
}

struct CookieCreation<'t> {
    node: Node<'t>,
    flags: CookieFlags,
}

/// csharpsquid:S2092 and csharpsquid:S3330 — session cookies without
/// `Secure` travel over plain HTTP, and cookies without `HttpOnly` are
/// readable from scripts. Bound: cookies created and configured inside
/// one member body, tracked by storage name.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for cookie in cookies_in_callable(body, source) {
            if !cookie.flags.secure {
                issues.push(issue(
                    language,
                    "S2092",
                    "Make sure creating this cookie without setting the 'Secure' property is safe here.",
                    range_of(cookie.node, source),
                ));
            }
            if !cookie.flags.http_only {
                issues.push(issue(
                    language,
                    "S3330",
                    "Make sure creating this cookie without the \"HttpOnly\" flag is safe.",
                    range_of(cookie.node, source),
                ));
            }
        }
    }
    issues
}

/// `HttpCookie` creations and their flags in one callable. Nested callables
/// are analyzed by their own [`callable_blocks`] entry, so their bindings and
/// setters cannot leak into the enclosing callable or be reported twice.
fn cookies_in_callable<'t>(body: Node<'t>, source: &str) -> Vec<CookieCreation<'t>> {
    let mut cookies = Vec::new();
    let mut cookie_by_node = HashMap::new();
    let mut current_cookie_by_name = HashMap::new();

    walk_owned(body, &mut |node| match node.kind() {
        "object_creation_expression" => {
            let Some(name) = cookie_creation_name(node, source) else {
                return;
            };
            let index = cookies.len();
            cookies.push(CookieCreation {
                node,
                flags: CookieFlags::default(),
            });
            cookie_by_node.insert(node.id(), index);
            current_cookie_by_name.insert(name, index);
        }
        "assignment_expression" => {
            let Some(property) = true_property_assignment(node, source) else {
                return;
            };
            let index = if let Some(name) = assigned_cookie_name(node, source) {
                current_cookie_by_name.get(name).copied()
            } else {
                enclosing_object_creation(node)
                    .and_then(|creation| cookie_by_node.get(&creation.id()).copied())
            };
            if let Some(index) = index {
                set_flag(&mut cookies[index].flags, property);
            }
        }
        _ => {}
    });

    cookies
}

/// Name that receives an `HttpCookie` creation. Unbound creations such as a
/// constructor passed directly as an argument stay outside this bounded rule.
fn cookie_creation_name<'s>(creation: Node<'_>, source: &'s str) -> Option<&'s str> {
    let is_cookie = creation
        .child_by_field_name("type")
        .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "HttpCookie");
    if !is_cookie {
        return None;
    }
    let parent = creation.parent()?;
    let bound = match parent.kind() {
        "variable_declarator" => parent.child_by_field_name("name"),
        "assignment_expression" => parent.child_by_field_name("left"),
        _ => None,
    }?;
    assignment_target_name(bound, source)
}

fn true_property_assignment<'s>(assignment: Node<'_>, source: &'s str) -> Option<&'s str> {
    if operator_of(assignment) != Some("=") {
        return None;
    }
    let right = assignment.child_by_field_name("right")?;
    if right.kind() != "boolean_literal" || node_text(right, source) != "true" {
        return None;
    }
    let left = assignment.child_by_field_name("left")?;
    let property = match left.kind() {
        "member_access_expression" => expression_name(left, source),
        "identifier" => Some(node_text(left, source)),
        _ => None,
    }?;
    matches!(property, "Secure" | "HttpOnly").then_some(property)
}

fn assigned_cookie_name<'s>(assignment: Node<'_>, source: &'s str) -> Option<&'s str> {
    let left = assignment.child_by_field_name("left")?;
    if left.kind() != "member_access_expression" {
        return None;
    }
    let base = left.child_by_field_name("expression")?;
    (base.kind() == "identifier").then(|| node_text(base, source))
}

fn enclosing_object_creation(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "object_creation_expression" {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn set_flag(flags: &mut CookieFlags, property: &str) {
    match property {
        "Secure" => flags.secure = true,
        "HttpOnly" => flags.http_only = true,
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn object_initializer_security_flags_are_recognized() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var cookie = new HttpCookie(\"session\")\n        {\n            Secure = true,\n            HttpOnly = true\n        };\n        Response.Cookies.Add(cookie);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2092").is_empty());
        assert!(with_key(&report, "csharpsquid:S3330").is_empty());
    }

    #[test]
    fn partial_object_initializer_still_reports_missing_flag() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var cookie = new HttpCookie(\"session\") { Secure = true };\n        Response.Cookies.Add(cookie);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2092").is_empty());
        assert_eq!(with_key(&report, "csharpsquid:S3330").len(), 1);
    }

    #[test]
    fn nested_callable_cookie_is_reported_once() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var outer = new HttpCookie(\"outer\");\n        void Local()\n        {\n            var inner = new HttpCookie(\"inner\");\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2092").len(), 2);
        assert_eq!(with_key(&report, "csharpsquid:S3330").len(), 2);
    }

    #[test]
    fn same_named_nested_binding_does_not_secure_outer_cookie() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var cookie = new HttpCookie(\"outer\");\n        void Local()\n        {\n            var cookie = new HttpCookie(\"inner\");\n            cookie.Secure = true;\n            cookie.HttpOnly = true;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2092").len(), 1);
        assert_eq!(with_key(&report, "csharpsquid:S3330").len(), 1);
    }
}
