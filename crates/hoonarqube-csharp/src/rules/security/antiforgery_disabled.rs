use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, direct_attributes, is_error_tainted, issue, node_text, range_of,
    simple_name,
};
use crate::rules::expressions::{binary_operands, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4502 — turning antiforgery off invites cross-site request
/// forgery.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues: Vec<Issue> = collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(target, value)| {
                node_text(target, source)
                    .to_ascii_lowercase()
                    .contains("ntiforgery")
                    && value.kind() == "boolean_literal"
                    && node_text(value, source) == "false"
            })
        })
        .map(|assignment| {
            issue(
                language,
                "S4502",
                "Keep antiforgery validation enabled.",
                range_of(assignment, source),
            )
        })
        .collect();

    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !is_aspnet_controller_action(root, method, source) {
            continue;
        }
        for attribute in direct_attributes(method) {
            if !framework_attribute(
                root,
                attribute,
                source,
                "IgnoreAntiforgeryToken",
                "Microsoft.AspNetCore.Mvc",
            ) {
                continue;
            }
            issues.push(issue(
                language,
                "S4502",
                "Ensure CSRF protection is not disabled.",
                range_of(attribute, source),
            ));
        }
    }
    issues
}

fn is_aspnet_controller_action(root: Node<'_>, method: Node<'_>, source: &str) -> bool {
    let Some(class) = ancestors_of(method).find(|ancestor| ancestor.kind() == "class_declaration")
    else {
        return false;
    };
    base_type_is_framework(
        root,
        class,
        source,
        "ControllerBase",
        "Microsoft.AspNetCore.Mvc",
    ) || base_type_is_framework(
        root,
        class,
        source,
        "Controller",
        "Microsoft.AspNetCore.Mvc",
    )
}

fn base_type_is_framework(
    root: Node<'_>,
    class: Node<'_>,
    source: &str,
    short: &str,
    namespace: &str,
) -> bool {
    let mut cursor = class.walk();
    class
        .children(&mut cursor)
        .filter(|child| child.kind() == "base_list")
        .flat_map(|base_list| {
            let mut list_cursor = base_list.walk();
            base_list
                .named_children(&mut list_cursor)
                .collect::<Vec<_>>()
        })
        .any(|base| framework_type(root, node_text(base, source), short, namespace, source))
}

fn framework_attribute(
    root: Node<'_>,
    attribute: Node<'_>,
    source: &str,
    short: &str,
    namespace: &str,
) -> bool {
    attribute
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
        .map(|name| name.strip_suffix("Attribute").unwrap_or(name))
        .is_some_and(|name| framework_type(root, name, short, namespace, source))
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4502_flags_ignore_antiforgery_on_a_real_controller_action() {
        let report = analyze_default(
            "using Microsoft.AspNetCore.Mvc;\n\n[ApiController]\npublic sealed class PaymentsController : ControllerBase\n{\n    [HttpPost]\n    [IgnoreAntiforgeryToken]\n    public IActionResult Transfer() => Ok();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4502");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Ensure CSRF protection is not disabled."
        );
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[0].range.start.column, 5);
        assert_eq!(flagged[0].range.end.line, 7);
        assert_eq!(flagged[0].range.end.column, 27);
    }

    #[test]
    fn s4502_keeps_enabled_and_class_guarded_antiforgery_controls_clean() {
        let safe = analyze_default(
            "using Microsoft.AspNetCore.Mvc;\n\n[ApiController]\npublic sealed class PaymentsController : ControllerBase\n{\n    [HttpPost]\n    [ValidateAntiForgeryToken]\n    public IActionResult Transfer() => Ok();\n}\n",
        );
        assert!(with_key(&safe, "csharpsquid:S4502").is_empty());

        let near_miss = analyze_default(
            "using Microsoft.AspNetCore.Mvc;\nusing Microsoft.AspNetCore.Mvc.ViewFeatures;\n\n[ApiController]\n[AutoValidateAntiforgeryToken]\npublic sealed class PaymentsController : ControllerBase\n{\n    [HttpPost]\n    public IActionResult Transfer() => Ok();\n}\n",
        );
        assert!(with_key(&near_miss, "csharpsquid:S4502").is_empty());
    }
}
