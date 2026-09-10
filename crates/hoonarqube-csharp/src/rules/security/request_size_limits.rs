use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, direct_attributes, is_error_tainted, issue, node_text, range_of,
    simple_name,
};
use crate::rules::expressions::{
    binary_operands, expression_name, first_named_child, integer_literal_value, operator_of,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5693 — request bodies beyond the tolerated size exhaust
/// server memory. `ControllerBase` action attributes are evaluated only when
/// their inline limit is a constant expression; helper-returned aliases stay
/// outside this bounded check.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const REQUEST_BODY_LIMIT_BYTES: u64 = 8_388_608;
    const LIMIT_TARGETS: [&str; 4] = [
        "MaxRequestBodySize",
        "MaxRequestBodyLength",
        "MultipartBodyLengthLimit",
        "FormSize",
    ];
    let mut issues = collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(target, value)| {
                expression_name(target, source).is_some_and(|name| LIMIT_TARGETS.contains(&name))
                    && value.kind() == "integer_literal"
                    && integer_literal_value(node_text(value, source))
                        .is_some_and(|bytes| bytes > REQUEST_BODY_LIMIT_BYTES)
            })
        })
        .map(|assignment| {
            issue(
                language,
                "S5693",
                format!("Keep request bodies at or below {REQUEST_BODY_LIMIT_BYTES} bytes."),
                range_of(assignment, source),
            )
        })
        .collect::<Vec<_>>();

    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !is_aspnet_controller_action(root, method, source) {
            continue;
        }
        for attribute in direct_attributes(method) {
            if !attribute_exceeds_request_limit(root, attribute, source, REQUEST_BODY_LIMIT_BYTES) {
                continue;
            }
            issues.push(issue(
                language,
                "S5693",
                "Limit the content length of HTTP requests.",
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

fn attribute_exceeds_request_limit(
    root: Node<'_>,
    attribute: Node<'_>,
    source: &str,
    request_body_limit: u64,
) -> bool {
    if framework_attribute(
        root,
        attribute,
        source,
        "DisableRequestSizeLimit",
        "Microsoft.AspNetCore.Mvc",
    ) {
        return true;
    }
    if framework_attribute(
        root,
        attribute,
        source,
        "RequestSizeLimit",
        "Microsoft.AspNetCore.Mvc",
    ) {
        return attribute_arguments(attribute)
            .first()
            .and_then(|argument| attribute_argument_value(*argument))
            .and_then(|value| integer_expression_value(value, source))
            .is_some_and(|bytes| bytes > request_body_limit);
    }
    if !framework_attribute(
        root,
        attribute,
        source,
        "RequestFormLimits",
        "Microsoft.AspNetCore.Mvc",
    ) {
        return false;
    }
    attribute_arguments(attribute)
        .into_iter()
        .filter_map(|argument| {
            let name = argument.child_by_field_name("name")?;
            (node_text(name, source) == "MultipartBodyLengthLimit")
                .then(|| attribute_argument_value(argument))
                .flatten()
        })
        .filter_map(|value| integer_expression_value(value, source))
        .any(|bytes| bytes > request_body_limit)
}

fn attribute_arguments(attribute: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(attribute, &["attribute_argument"])
}

fn attribute_argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = argument.walk();
    argument.named_children(&mut cursor).last()
}

fn integer_expression_value(expression: Node<'_>, source: &str) -> Option<u64> {
    match expression.kind() {
        "integer_literal" => integer_literal_value(node_text(expression, source)),
        "parenthesized_expression" => {
            first_named_child(expression).and_then(|inner| integer_expression_value(inner, source))
        }
        "binary_expression" => {
            let (left, right) = binary_operands(expression)?;
            let left = integer_expression_value(left, source)?;
            let right = integer_expression_value(right, source)?;
            match operator_of(expression)? {
                "+" => left.checked_add(right),
                "-" => left.checked_sub(right),
                "*" => left.checked_mul(right),
                "/" if right != 0 => left.checked_div(right),
                "%" if right != 0 => left.checked_rem(right),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5693_requires_an_exact_limit_member_name() {
        let report = analyze_default(
            "class Options { long BackupMaxRequestBodySize; void Set() { BackupMaxRequestBodySize = 9000000; } }",
        );
        assert!(with_key(&report, "csharpsquid:S5693").is_empty());
    }
    #[test]
    fn s5693_flags_oversized_controller_request_limit_attributes() {
        let report = analyze_default(
            "using Microsoft.AspNetCore.Mvc;\n\n[ApiController]\npublic sealed class UploadLimitsController : ControllerBase\n{\n    [HttpPost]\n    [DisableRequestSizeLimit]\n    public IActionResult Unbounded() => Ok();\n\n    [HttpPost]\n    [RequestSizeLimit(10 * 1024 * 1024)]\n    public IActionResult LargeRequest() => Ok();\n\n    [HttpPost]\n    [RequestFormLimits(MultipartBodyLengthLimit = 20 * 1024 * 1024)]\n    public IActionResult LargeMultipart() => Ok();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5693");
        for finding in &flagged {
            assert_eq!(
                finding.message,
                "Limit the content length of HTTP requests."
            );
        }
        assert_eq!(
            flagged
                .iter()
                .map(|finding| finding.range.start.line)
                .collect::<Vec<_>>(),
            vec![7, 11, 15]
        );
    }

    #[test]
    fn s5693_keeps_bounded_controller_request_limits_clean() {
        let safe = analyze_default(
            "using Microsoft.AspNetCore.Mvc;\n\n[ApiController]\npublic sealed class UploadLimitsController : ControllerBase\n{\n    [HttpPost]\n    [RequestSizeLimit(2 * 1024 * 1024)]\n    public IActionResult Request() => Ok();\n\n    [HttpPost]\n    [RequestFormLimits(MultipartBodyLengthLimit = 8 * 1024 * 1024)]\n    public IActionResult Multipart() => Ok();\n}\n",
        );
        assert!(with_key(&safe, "csharpsquid:S5693").is_empty());

        let near_miss = analyze_default(
            "using Microsoft.AspNetCore.Mvc;\n\n[ApiController]\npublic sealed class UploadLimitsAliasController : ControllerBase\n{\n    [HttpPost]\n    [RequestSizeLimit(1 * 1024 * 1024)]\n    [RequestFormLimits(MultipartBodyLengthLimit = 1 * 1024 * 1024)]\n    public IActionResult Upload() => Ok();\n}\n",
        );
        assert!(with_key(&near_miss, "csharpsquid:S5693").is_empty());
    }
}
