use super::support::argument_nodes;
use super::support::is_regex_creation;
use super::support::regex_static_pattern;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6444 — every Regex construction and static pattern call
/// carries a timeout.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if !is_regex_creation(creation, source) {
            continue;
        }
        let Some(arguments) = creation.child_by_field_name("arguments") else {
            continue;
        };
        if !arguments_carry_timeout(arguments, source) {
            issues.push(issue(
                language,
                "S6444",
                "Pass a timeout to limit the execution time.",
                range_of(creation, source),
            ));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if regex_static_pattern(invocation, source).is_none() {
            continue;
        }
        let timed_out = invocation
            .child_by_field_name("arguments")
            .is_some_and(|arguments| arguments_carry_timeout(arguments, source));
        if !timed_out {
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

/// Whether an argument names an explicit timeout carrier. Identifier
/// boundaries avoid treating unrelated names such as `notATimeSpanValue` as
/// proof that a timeout was supplied.
fn arguments_carry_timeout(arguments: Node<'_>, source: &str) -> bool {
    argument_nodes(arguments).iter().any(|argument| {
        collect_kinds(*argument, &["identifier"])
            .into_iter()
            .any(|identifier| {
                matches!(
                    node_text(identifier, source),
                    "TimeSpan" | "InfiniteMatchTimeout"
                )
            })
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn regex_rules_support_qualified_types_and_exact_timeout_identifiers() {
        let report = analyze_default(
            "class C\n{\n    void M(string input, object notATimeSpanValue)\n    {\n        var a = new System.Text.RegularExpressions.Regex(\"(\");\n        var b = System.Text.RegularExpressions.Regex.IsMatch(input, \"(\", notATimeSpanValue);\n        var c = System.Text.RegularExpressions.Regex.IsMatch(input, \"ok\", RegexOptions.None, System.TimeSpan.FromSeconds(1));\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S5856").len(), 2);
        let timeouts = with_key(&report, "csharpsquid:S6444");
        assert_eq!(timeouts.len(), 2);
        assert_eq!(timeouts[0].range.start.line, 5);
        assert_eq!(timeouts[1].range.start.line, 6);
    }
}
