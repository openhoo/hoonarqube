use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::expressions::{
    callee_name, first_named_child, invocation_receiver, operator_of, resolved_identifier_type,
};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4507 — shipping with debugging enabled hands attackers a
/// detailed map of the application. Developer exception middleware is checked
/// only on typed ASP.NET Core builders and is allowed under a positive
/// `IsDevelopment()` guard.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        let debug_on = (lowered.contains("customerrors") && lowered.contains("off"))
            || (lowered.contains("debug=") && lowered.contains("true"));
        if debug_on {
            issues.push(issue(
                language,
                "S4507",
                "Disable debugging features in production.",
                range_of(literal, source),
            ));
        }
    }

    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || callee_name(invocation, source) != Some("UseDeveloperExceptionPage")
            || !is_aspnet_builder_call(root, invocation, source)
            || is_development_guarded(root, invocation, source)
        {
            continue;
        }
        issues.push(issue(
            language,
            "S4507",
            "Disable this debug feature in production.",
            range_of(invocation, source),
        ));
    }
    issues
}

fn is_aspnet_builder_call(root: Node<'_>, invocation: Node<'_>, source: &str) -> bool {
    invocation_receiver(invocation).is_some_and(|receiver| {
        resolved_identifier_type(receiver, source)
            .into_iter()
            .chain(std::iter::once(node_text(receiver, source)))
            .any(|ty| {
                framework_type(
                    root,
                    ty,
                    "WebApplication",
                    "Microsoft.AspNetCore.Builder",
                    source,
                ) || framework_type(
                    root,
                    ty,
                    "IApplicationBuilder",
                    "Microsoft.AspNetCore.Builder",
                    source,
                )
            })
    })
}

fn framework_type(
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
    collect_kinds(root, &["using_directive"])
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
    collect_kinds(root, &["using_directive"])
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
    collect_kinds(
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

fn is_development_guarded(root: Node<'_>, invocation: Node<'_>, source: &str) -> bool {
    let mut ancestor = invocation.parent();
    while let Some(node) = ancestor {
        if is_callable_boundary(node.kind()) {
            break;
        }
        if node.kind() == "if_statement"
            && node
                .child_by_field_name("condition")
                .zip(node.child_by_field_name("consequence"))
                .is_some_and(|(condition, consequence)| {
                    is_descendant_or_self(invocation, consequence)
                        && positive_development_condition(root, condition, source)
                })
        {
            return true;
        }
        ancestor = node.parent();
    }
    false
}

fn is_descendant_or_self(node: Node<'_>, ancestor: Node<'_>) -> bool {
    node.id() == ancestor.id() || ancestors_of(node).any(|parent| parent.id() == ancestor.id())
}

fn is_callable_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "constructor_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "anonymous_method_expression"
            | "accessor_declaration"
    )
}

fn positive_development_condition(root: Node<'_>, condition: Node<'_>, source: &str) -> bool {
    match condition.kind() {
        "parenthesized_expression" => first_named_child(condition)
            .is_some_and(|inner| positive_development_condition(root, inner, source)),
        "unary_expression" if operator_of(condition) == Some("!") => false,
        "binary_expression" => {
            let Some((left, right)) = crate::rules::expressions::binary_operands(condition) else {
                return false;
            };
            match operator_of(condition) {
                Some("&&") => {
                    positive_development_condition(root, left, source)
                        || positive_development_condition(root, right, source)
                }
                Some("||") => {
                    positive_development_condition(root, left, source)
                        && positive_development_condition(root, right, source)
                }
                Some("==" | "!=") => {
                    let (check, literal) = if right.kind() == "boolean_literal" {
                        (left, right)
                    } else if left.kind() == "boolean_literal" {
                        (right, left)
                    } else {
                        return false;
                    };
                    let enabled = node_text(literal, source) == "true";
                    (operator_of(condition) == Some("==") && enabled
                        || operator_of(condition) == Some("!=") && !enabled)
                        && positive_development_condition(root, check, source)
                }
                _ => false,
            }
        }
        "invocation_expression" => is_development_check(root, condition, source),
        _ => false,
    }
}

fn is_development_check(root: Node<'_>, invocation: Node<'_>, source: &str) -> bool {
    if callee_name(invocation, source) != Some("IsDevelopment") {
        return false;
    }
    let Some(receiver) = invocation_receiver(invocation) else {
        return false;
    };
    let mut candidates = Vec::new();
    if let Some(ty) = resolved_identifier_type(receiver, source) {
        candidates.push(ty);
    }
    candidates.push(simple_name(node_text(receiver, source)));
    candidates.into_iter().any(|ty| {
        framework_type(root, ty, "Environment", "System", source)
            || (ty == "Environment" && !has_local_type(root, "Environment", source))
            || framework_type(
                root,
                ty,
                "IHostEnvironment",
                "Microsoft.Extensions.Hosting",
                source,
            )
            || framework_type(
                root,
                ty,
                "IWebHostEnvironment",
                "Microsoft.AspNetCore.Hosting",
                source,
            )
            || framework_type(
                root,
                ty,
                "IHostingEnvironment",
                "Microsoft.AspNetCore.Hosting",
                source,
            )
    })
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4507_flags_developer_exception_page_and_respects_development_guards() {
        let report = analyze_default(
            "using Microsoft.AspNetCore.Builder;\n\npublic static class DiagnosticsPipeline\n{\n    public static WebApplication Configure(WebApplication app)\n    {\n        app.UseDeveloperExceptionPage();\n        return app;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4507");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Disable this debug feature in production."
        );
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[0].range.start.column, 8);
        assert_eq!(flagged[0].range.end.line, 7);
        assert_eq!(flagged[0].range.end.column, 39);

        let guarded = analyze_default(
            "using Microsoft.AspNetCore.Builder;\n\npublic static class DiagnosticsPipeline\n{\n    public static WebApplication Configure(WebApplication app)\n    {\n        if (app.Environment.IsDevelopment())\n        {\n            app.UseDeveloperExceptionPage();\n        }\n        return app;\n    }\n}\n",
        );
        assert!(with_key(&guarded, "csharpsquid:S4507").is_empty());
    }

    #[test]
    fn s4507_flags_developer_exception_page_in_a_production_else_branch() {
        let report = analyze_default(
            "using Microsoft.AspNetCore.Builder;\n\npublic static class DiagnosticsPipeline\n{\n    public static WebApplication Configure(WebApplication app)\n    {\n        if (app.Environment.IsDevelopment())\n        {\n            return app;\n        }\n        else\n        {\n            app.UseDeveloperExceptionPage();\n        }\n        return app;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4507").len(), 1);
    }
    #[test]
    fn s4507_keeps_production_exception_handler_clean() {
        let report = analyze_default(
            "using Microsoft.AspNetCore.Builder;\n\npublic static class DiagnosticsPipeline\n{\n    public static WebApplication Configure(WebApplication app)\n    {\n        app.UseExceptionHandler(\"/error\");\n        return app;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4507").is_empty());
    }
}
