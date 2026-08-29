use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::expressions::{
    callee_name, invocation_arguments, invocation_function, invocation_receiver,
};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6575 — pass the original timezone identifier directly to
/// `TimeZoneInfo` instead of converting it first.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut reported = std::collections::HashSet::new();
    for invocation in collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| {
            !is_error_tainted(*invocation)
                && callee_name(*invocation, source) == Some("FindSystemTimeZoneById")
                && invocation_receiver(*invocation).is_some_and(|receiver| {
                    simple_name(node_text(receiver, source).trim()) == "TimeZoneInfo"
                })
        })
    {
        let converted = lookup_converter(invocation, source);
        if let Some(converter) = converted
            && reported.insert(converter.id())
        {
            let anchor = invocation_function(converter)
                .and_then(|function| function.child_by_field_name("name"))
                .unwrap_or(converter);
            let converter_name = callee_name(converter, source).unwrap_or("converter");
            issues.push(issue(
                language,
                "S6575",
                format!(
                    "Use \"TimeZoneInfo.FindSystemTimeZoneById\" directly instead of \"TZConvert.{converter_name}\""
                ),
                range_of(anchor, source),
            ));
        }
    }
    issues
}

fn lookup_converter<'t>(lookup: Node<'t>, source: &str) -> Option<Node<'t>> {
    let argument = invocation_arguments(lookup)
        .first()
        .copied()
        .map(argument_expression)?;
    if let Some(converter) = converter_invocation(argument, source) {
        return Some(converter);
    }
    if argument.kind() != "identifier" {
        return None;
    }
    let argument_name = node_text(argument, source);
    let method = ancestors_of(lookup).find(|ancestor| ancestor.kind() == "method_declaration")?;
    collect_kinds(method, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.start_byte() < lookup.start_byte())
        .filter(|declarator| {
            declarator
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == argument_name)
        })
        .filter_map(|declarator| converter_invocation(declarator, source))
        .max_by_key(tree_sitter::Node::start_byte)
}

fn converter_invocation<'t>(scope: Node<'t>, source: &str) -> Option<Node<'t>> {
    collect_kinds(scope, &["invocation_expression"])
        .into_iter()
        .find(|invocation| {
            matches!(
                callee_name(*invocation, source),
                Some("IanaToWindows" | "WindowsToIana")
            ) && invocation_receiver(*invocation).is_some_and(|receiver| {
                simple_name(node_text(receiver, source).trim()) == "TZConvert"
            })
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6575_requires_the_converted_value_to_flow_into_lookup() {
        let report = analyze_default(
            "class Zones\n{\n    TimeZoneInfo Resolve(string id)\n    {\n        var windows = TZConvert.IanaToWindows(id);\n        UseElsewhere(windows);\n        return TimeZoneInfo.FindSystemTimeZoneById(id);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6575").is_empty());
    }

    #[test]
    fn s6575_reports_each_converter_once_and_anchors_its_name() {
        let report = analyze_default(
            "class Zones\n{\n    TimeZoneInfo Resolve(string id)\n    {\n        var windows = TZConvert.IanaToWindows(id);\n        var first = TimeZoneInfo.FindSystemTimeZoneById(windows);\n        return TimeZoneInfo.FindSystemTimeZoneById(windows);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6575");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert!(flagged[0].message.contains("IanaToWindows"));
    }

    #[test]
    fn s6575_tracks_direct_converter_arguments() {
        let report = analyze_default(
            "class Zones\n{\n    TimeZoneInfo Resolve(string id) => TimeZoneInfo.FindSystemTimeZoneById(TZConvert.WindowsToIana(id));\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6575");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("WindowsToIana"));
    }

    #[test]
    fn s6575_requires_exact_framework_receivers() {
        let report = analyze_default(
            "class Zones\n{\n    object Resolve(string id)\n    {\n        var windows = MyTZConvert.IanaToWindows(id);\n        return CustomTimeZoneInfo.FindSystemTimeZoneById(windows);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6575").is_empty());
    }
}
