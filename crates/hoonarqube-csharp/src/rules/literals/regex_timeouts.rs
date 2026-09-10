use super::support::{
    argument_nodes, declarator_initializer, is_regex_creation, regex_static_pattern,
};
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of,
};
use crate::rules::expressions::{
    callee_name, expression_name, first_named_child, invocation_receiver,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6444 — every Regex construction and static pattern call
/// carries a timeout or uses the non-backtracking engine.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation)
            || !is_framework_type_reference(
                node_text(
                    creation.child_by_field_name("type").unwrap_or(creation),
                    source,
                ),
                "Regex",
            )
            || !is_regex_creation(creation, source)
        {
            continue;
        }
        let Some(arguments) = creation.child_by_field_name("arguments") else {
            continue;
        };
        let args = argument_nodes(arguments);
        let timed = has_timeout_at_positions(&args, &[2], source)
            || has_non_backtracking_option(arguments, source);
        if !timed {
            issues.push(issue(
                language,
                "S6444",
                "Pass a timeout to limit the execution time.",
                range_of(creation, source),
            ));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || regex_static_pattern(invocation, source).is_none()
            || !invocation_receiver(invocation).is_some_and(|receiver| {
                is_framework_type_reference(node_text(receiver, source), "Regex")
            })
        {
            continue;
        }
        let timed = invocation
            .child_by_field_name("arguments")
            .is_some_and(|arguments| {
                let positions = if callee_name(invocation, source) == Some("Replace") {
                    &[4][..]
                } else {
                    &[3][..]
                };
                has_timeout_at_positions(&argument_nodes(arguments), positions, source)
                    || has_non_backtracking_option(arguments, source)
            });
        if !timed {
            issues.push(issue(
                language,
                "S6444",
                "Pass a timeout to limit the execution time.",
                range_of(invocation, source),
            ));
        }
    }
    issues
}

fn has_timeout_at_positions(arguments: &[Node<'_>], positions: &[usize], source: &str) -> bool {
    arguments.iter().enumerate().any(|(index, argument)| {
        let named_timeout = argument
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == "matchTimeout");
        (positions.contains(&index) || named_timeout) && has_timeout_argument(*argument, source)
    })
}

fn has_timeout_argument(argument: Node<'_>, source: &str) -> bool {
    let expression = actual_argument_expression(argument);
    is_direct_timeout_expression(expression, source)
        || (expression.kind() == "identifier" && is_timeout_alias(expression, source))
}

fn actual_argument_expression(argument: Node<'_>) -> Node<'_> {
    let mut cursor = argument.walk();
    argument
        .named_children(&mut cursor)
        .last()
        .unwrap_or(argument)
}

fn is_direct_timeout_expression(expression: Node<'_>, source: &str) -> bool {
    if expression.kind() == "invocation_expression" {
        let Some(receiver) = invocation_receiver(expression) else {
            return false;
        };
        return is_framework_type_reference(node_text(receiver, source), "TimeSpan")
            && matches!(
                callee_name(expression, source),
                Some(
                    "FromDays"
                        | "FromHours"
                        | "FromMilliseconds"
                        | "FromMinutes"
                        | "FromSeconds"
                        | "FromTicks"
                )
            );
    }
    if expression.kind() == "object_creation_expression" {
        return expression
            .child_by_field_name("type")
            .is_some_and(|type_node| {
                is_framework_type_reference(node_text(type_node, source), "TimeSpan")
            });
    }
    expression.kind() == "member_access_expression"
        && expression_name(expression, source) == Some("InfiniteMatchTimeout")
        && first_named_child(expression).is_some_and(|receiver| {
            is_framework_type_reference(node_text(receiver, source), "Regex")
        })
}

fn is_framework_type_reference(text: &str, short_name: &str) -> bool {
    let text = text.trim();
    matches!(
        (short_name, text),
        (
            "TimeSpan",
            "TimeSpan" | "System.TimeSpan" | "global::System.TimeSpan"
        ) | (
            "Regex",
            "Regex"
                | "System.Text.RegularExpressions.Regex"
                | "global::System.Text.RegularExpressions.Regex"
        ) | (
            "RegexOptions",
            "RegexOptions"
                | "System.Text.RegularExpressions.RegexOptions"
                | "global::System.Text.RegularExpressions.RegexOptions"
        )
    )
}

fn is_timeout_alias(identifier: Node<'_>, source: &str) -> bool {
    let Some(callable) = ancestors_of(identifier).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "local_function_statement"
                | "anonymous_method_expression"
                | "lambda_expression"
        )
    }) else {
        return false;
    };
    if parameters_of(callable).into_iter().any(|parameter| {
        parameter
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == node_text(identifier, source))
            && parameter
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    is_framework_type_reference(node_text(type_node, source), "TimeSpan")
                })
    }) {
        return true;
    }
    collect_kinds(callable, &["variable_declaration"])
        .into_iter()
        .filter(|declaration| declaration.start_byte() < identifier.start_byte())
        .rev()
        .find_map(|declaration| {
            collect_kinds(declaration, &["variable_declarator"])
                .into_iter()
                .find_map(|declarator| {
                    let name = declarator.child_by_field_name("name")?;
                    (node_text(name, source) == node_text(identifier, source))
                        .then_some((declarator, name))
                })
                .and_then(|(declarator, name)| declarator_initializer(declarator, name))
        })
        .is_some_and(|initializer| is_direct_timeout_expression(initializer, source))
}

fn has_non_backtracking_option(arguments: Node<'_>, source: &str) -> bool {
    argument_nodes(arguments).into_iter().any(|argument| {
        let expression = actual_argument_expression(argument);
        expression.kind() == "member_access_expression"
            && expression_name(expression, source) == Some("NonBacktracking")
            && first_named_child(expression).is_some_and(|receiver| {
                is_framework_type_reference(node_text(receiver, source), "RegexOptions")
            })
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6444_flags_regex_construction_and_static_calls_without_timeout() {
        let report = analyze_default(
            "using System.Text.RegularExpressions;\n\npublic static class RegexUse\n{\n    public static bool Check(string input)\n    {\n        var compiled = new Regex(\"\\\\d+\");\n        return compiled.IsMatch(input) || Regex.IsMatch(input, \"(a+)+$\");\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S6444");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 7);
        assert_eq!(found[1].range.start.line, 8);
    }

    #[test]
    fn s6444_accepts_real_timeout_overloads_and_aliases() {
        let report = analyze_default(
            "using System;\nusing System.Text.RegularExpressions;\n\npublic static class RegexUse\n{\n    public static bool Check(string input)\n    {\n        var timeout = TimeSpan.FromSeconds(5);\n        var compiled = new Regex(\"\\\\d+\", RegexOptions.None, timeout);\n        return compiled.IsMatch(input)\n            || Regex.IsMatch(input, \"(a+)+$\", RegexOptions.None, timeout);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6444").is_empty());

        let non_backtracking = analyze_default(
            "using System.Text.RegularExpressions;\npublic static class RegexUseAlias\n{\n    public static bool Check(string input)\n        => Regex.IsMatch(input, \"(a+)+$\", RegexOptions.NonBacktracking);\n}\n",
        );
        assert!(with_key(&non_backtracking, "csharpsquid:S6444").is_empty());
    }

    #[test]
    fn s6444_does_not_treat_unrelated_argument_names_as_timeouts() {
        let report = analyze_default(
            "using System.Text.RegularExpressions;\nclass C\n{\n    bool Check(string input, object notATimeSpanValue)\n        => Regex.IsMatch(input, \"(\", RegexOptions.None, notATimeSpanValue);\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6444").len(), 1);
    }
}
