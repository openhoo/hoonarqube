use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, direct_attributes, is_error_tainted, issue, node_text, range_of,
    simple_name,
};
use crate::rules::expressions::{invocation_arguments, invocation_targets};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5753 — disabling request validation reopens the XSS door.
/// MVC attribute checks are bounded to direct actions on Controller-derived
/// types; helper aliases remain outside this structural check.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = literal_validation_issues(root, source, language);
    issues.extend(invocation_validation_issues(root, source, language));
    issues.extend(controller_attribute_issues(root, source, language));
    issues
}

fn literal_validation_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        if lowered.contains("validaterequest") && lowered.contains("false") {
            issues.push(issue(
                language,
                "S5753",
                "Keep ASP.NET request validation enabled.",
                range_of(literal, source),
            ));
        }
    }
    issues
}

fn invocation_validation_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || !invocation_targets(invocation, source, None, &["ValidateInput"])
        {
            continue;
        }
        let disables = invocation_arguments(invocation)
            .iter()
            .any(|argument| node_text(*argument, source) == "false");
        if disables {
            issues.push(issue(
                language,
                "S5753",
                "Keep ASP.NET request validation enabled.",
                range_of(invocation, source),
            ));
        }
    }
    issues
}

fn controller_attribute_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !is_mvc_controller_action(root, method, source) {
            continue;
        }
        for attribute in direct_attributes(method) {
            if !framework_attribute(root, attribute, source, "ValidateInput", "System.Web.Mvc")
                || !attribute_disables_validation(attribute, source)
            {
                continue;
            }
            issues.push(issue(
                language,
                "S5753",
                "Ensure ASP.NET Request Validation is not disabled.",
                range_of(attribute, source),
            ));
        }
    }
    issues
}

fn is_mvc_controller_action(root: Node<'_>, method: Node<'_>, source: &str) -> bool {
    let Some(class) = ancestors_of(method).find(|ancestor| ancestor.kind() == "class_declaration")
    else {
        return false;
    };
    base_type_is_framework(root, class, source)
}

fn base_type_is_framework(root: Node<'_>, class: Node<'_>, source: &str) -> bool {
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
        .any(|base| {
            framework_type(
                root,
                node_text(base, source),
                "Controller",
                "System.Web.Mvc",
                source,
            )
        })
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

fn attribute_disables_validation(attribute: Node<'_>, source: &str) -> bool {
    collect_kinds(attribute, &["attribute_argument"])
        .into_iter()
        .filter_map(|argument| {
            let mut cursor = argument.walk();
            argument.named_children(&mut cursor).last()
        })
        .any(|value| value.kind() == "boolean_literal" && node_text(value, source) == "false")
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5753_flags_real_mvc_validate_input_attribute() {
        let report = analyze_default(
            "using System.Web.Mvc;\n\npublic sealed class LegacyController : Controller\n{\n    [ValidateInput(false)]\n    public ActionResult Welcome(string name)\n        => Content(name);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5753");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Ensure ASP.NET Request Validation is not disabled."
        );
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[0].range.start.column, 5);
        assert_eq!(flagged[0].range.end.line, 5);
        assert_eq!(flagged[0].range.end.column, 25);
    }

    #[test]
    fn s5753_keeps_enabled_mvc_attributes_and_aliases_clean() {
        let safe = analyze_default(
            "using System.Web.Mvc;\n\npublic sealed class LegacyController : Controller\n{\n    [ValidateInput(true)]\n    public ActionResult Welcome(string name)\n        => Content(name);\n}\n",
        );
        assert!(with_key(&safe, "csharpsquid:S5753").is_empty());

        let near_miss = analyze_default(
            "using System.Web.Mvc;\n\npublic sealed class LegacyControllerAlias : Controller\n{\n    public ActionResult Welcome(string name)\n        => ValidatedContent(name);\n\n    [ValidateInput(true)]\n    private ActionResult ValidatedContent(string name)\n        => Content(name);\n}\n",
        );
        assert!(with_key(&near_miss, "csharpsquid:S5753").is_empty());
    }
}
