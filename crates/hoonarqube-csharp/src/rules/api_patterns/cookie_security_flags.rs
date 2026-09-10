use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of, simple_name};
use crate::rules::dataflow::{callable_blocks, walk_owned};
use crate::rules::expressions::{
    callee_name, expression_name, invocation_arguments, invocation_receiver, operator_of,
    resolved_identifier_type,
};
use crate::rules::literals::{argument_expression, assignment_target_name};
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
/// readable from scripts. Legacy `HttpCookie` bindings stay callable-local;
/// ASP.NET Core `HttpResponse.Cookies.Append` is bounded to inline
/// framework `CookieOptions`, so helper-returned aliases stay unresolved.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for cookie in cookies_in_callable(body, source) {
            push_missing_cookie_flags(&mut issues, language, cookie.node, &cookie.flags, source);
        }
    }

    for append in collect_append_calls(root, source) {
        push_missing_cookie_flags(&mut issues, language, append.node, &append.flags, source);
    }
    issues
}

fn push_missing_cookie_flags(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    node: Node<'_>,
    flags: &CookieFlags,
    source: &str,
) {
    if !flags.secure {
        issues.push(issue(
            language,
            "S2092",
            "Set the 'Secure' flag on this cookie.",
            range_of(node, source),
        ));
    }
    if !flags.http_only {
        issues.push(issue(
            language,
            "S3330",
            "Set the 'HttpOnly' flag on this cookie.",
            range_of(node, source),
        ));
    }
}

struct AppendCookie<'t> {
    node: Node<'t>,
    flags: CookieFlags,
}

fn collect_append_calls<'t>(root: Node<'t>, source: &str) -> Vec<AppendCookie<'t>> {
    crate::cst::collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !crate::cst::is_error_tainted(*call))
        .filter(|call| callee_name(*call, source) == Some("Append"))
        .filter(|call| {
            invocation_receiver(*call)
                .is_some_and(|receiver| is_http_response_cookies(root, receiver, source))
        })
        .filter_map(|call| {
            let options = invocation_arguments(call)
                .get(2)
                .copied()
                .map(argument_expression)?;
            let (node, flags) = cookie_options(root, options, source)?;
            Some(AppendCookie { node, flags })
        })
        .collect()
}

fn is_http_response_cookies(root: Node<'_>, receiver: Node<'_>, source: &str) -> bool {
    if receiver.kind() != "member_access_expression"
        || expression_name(receiver, source) != Some("Cookies")
    {
        return false;
    }
    let Some(response) = receiver.child_by_field_name("expression") else {
        return false;
    };
    resolved_identifier_type(response, source).is_some_and(|ty| {
        is_framework_type(
            root,
            ty,
            "HttpResponse",
            "Microsoft.AspNetCore.Http",
            source,
        )
    })
}

fn is_framework_type(
    root: Node<'_>,
    type_text: &str,
    short: &str,
    namespace: &str,
    source: &str,
) -> bool {
    let trimmed = type_text.trim().trim_end_matches('?');
    let qualified = format!("{namespace}.{short}");
    let global = format!("global::{qualified}");
    if trimmed == qualified || trimmed == global {
        return true;
    }
    if let Some(alias_target) = using_alias_target(root, trimmed, source) {
        return alias_target == qualified || alias_target == global;
    }
    let alias_spelling = trimmed.strip_prefix("global::").unwrap_or(trimmed);
    if let Some((alias, suffix)) = alias_spelling.split_once('.')
        && using_alias_target(root, alias, source)
            .is_some_and(|target| format!("{target}.{suffix}") == qualified)
    {
        return true;
    }
    trimmed == short
        && !has_local_type(root, short, source)
        && (has_namespace_using(root, namespace, source)
            || using_alias_target(root, short, source).is_some())
}

fn using_alias_target<'a>(root: Node<'_>, wanted: &str, source: &'a str) -> Option<&'a str> {
    crate::cst::collect_kinds(root, &["using_directive"])
        .into_iter()
        .find_map(|using| {
            let alias = using.child_by_field_name("name")?;
            (node_text(alias, source) == wanted).then(|| {
                let mut cursor = using.walk();
                using
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "type")
                    .map(|target| node_text(target, source))
            })?
        })
}

fn has_namespace_using(root: Node<'_>, wanted: &str, source: &str) -> bool {
    crate::cst::collect_kinds(root, &["using_directive"])
        .into_iter()
        .any(|using| {
            if using.child_by_field_name("name").is_some() {
                return false;
            }
            let mut cursor = using.walk();
            using
                .named_children(&mut cursor)
                .next()
                .is_some_and(|target| node_text(target, source).trim() == wanted)
        })
}

fn has_local_type(root: Node<'_>, wanted: &str, source: &str) -> bool {
    crate::cst::collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
            "interface_declaration",
            "enum_declaration",
        ],
    )
    .into_iter()
    .filter_map(|declaration| declaration.child_by_field_name("name"))
    .any(|name| simple_name(node_text(name, source)) == wanted)
}

fn cookie_options<'t>(
    root: Node<'_>,
    expression: Node<'t>,
    source: &str,
) -> Option<(Node<'t>, CookieFlags)> {
    if expression.kind() != "object_creation_expression" {
        return None;
    }
    let type_node = expression.child_by_field_name("type")?;
    if !is_framework_type(
        root,
        node_text(type_node, source),
        "CookieOptions",
        "Microsoft.AspNetCore.Http",
        source,
    ) {
        return None;
    }

    let mut flags = CookieFlags::default();
    if let Some(initializer) = expression.child_by_field_name("initializer") {
        let mut cursor = initializer.walk();
        for member in initializer.named_children(&mut cursor) {
            if member.kind() != "assignment_expression"
                || operator_of(member) != Some("=")
                || member.child_by_field_name("right").is_none_or(|right| {
                    right.kind() != "boolean_literal" || node_text(right, source) != "true"
                })
            {
                continue;
            }
            let Some(left) = member.child_by_field_name("left") else {
                continue;
            };
            if let Some(property) = expression_name(left, source) {
                set_flag(&mut flags, property);
            }
        }
    }
    Some((expression, flags))
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
    #[test]
    fn aspnet_core_cookie_options_report_the_missing_secure_flag() {
        let report = analyze_default(
            "using Microsoft.AspNetCore.Http;\n\npublic static class SessionCookie\n{\n    public static void Issue(HttpResponse response)\n    {\n        response.Cookies.Append(\"session\", \"value\", new CookieOptions\n        {\n            HttpOnly = true,\n            SameSite = SameSiteMode.Lax,\n        });\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2092");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].message, "Set the 'Secure' flag on this cookie.");
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[0].range.end.line, 11);
        assert!(with_key(&report, "csharpsquid:S3330").is_empty());
    }

    #[test]
    fn aspnet_core_cookie_options_report_the_missing_http_only_flag() {
        let report = analyze_default(
            "using Microsoft.AspNetCore.Http;\n\npublic static class TicketCookie\n{\n    public static void Issue(HttpResponse response)\n    {\n        response.Cookies.Append(\"ticket\", \"value\", new CookieOptions\n        {\n            Secure = true,\n            SameSite = SameSiteMode.Strict,\n        });\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3330");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Set the 'HttpOnly' flag on this cookie."
        );
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[0].range.end.line, 11);
        assert!(with_key(&report, "csharpsquid:S2092").is_empty());
    }

    #[test]
    fn aspnet_core_cookie_option_aliases_stay_outside_the_bounded_check() {
        let report = analyze_default(
            "using Microsoft.AspNetCore.Http;\n\npublic static class SessionCookieAlias\n{\n    public static void Issue(HttpResponse response)\n        => response.Cookies.Append(\"session\", \"value\", BuildOptions());\n\n    private static CookieOptions BuildOptions() => new()\n    {\n        HttpOnly = true,\n        Secure = true,\n        SameSite = SameSiteMode.Lax,\n    };\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2092").is_empty());
        assert!(with_key(&report, "csharpsquid:S3330").is_empty());
    }
}
