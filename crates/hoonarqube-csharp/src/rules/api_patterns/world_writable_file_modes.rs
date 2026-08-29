use super::support::collect_kinds_in_callable;
use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::dataflow::callable_blocks;
use crate::rules::expressions::{callee_name, expression_name, invocation_arguments, operator_of};
use crate::rules::literals::{
    argument_expression, assignment_target_name, declarator_initializer, literal_inner_text,
};
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

/// csharpsquid:S2612 — permission rules that allow the broad `Everyone`
/// identity are security-sensitive when installed on a filesystem ACL.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        issues.extend(check_body(body, source, language));
    }
    issues
}

fn check_body(body: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut unsafe_rules: HashSet<&str> = HashSet::new();
    let mut issues = Vec::new();
    for node in collect_kinds_in_callable(
        body,
        &[
            "variable_declarator",
            "assignment_expression",
            "invocation_expression",
        ],
    ) {
        match node.kind() {
            "variable_declarator" => {
                let Some(name_node) = node.child_by_field_name("name") else {
                    continue;
                };
                let name = node_text(name_node, source);
                let unsafe_value = declarator_initializer(node, name_node)
                    .is_some_and(|value| is_unsafe_rule(value, source));
                if unsafe_value {
                    unsafe_rules.insert(name);
                } else {
                    unsafe_rules.remove(name);
                }
            }
            "assignment_expression" if operator_of(node) == Some("=") => {
                let Some(left) = node.child_by_field_name("left") else {
                    continue;
                };
                let Some(name) = assignment_target_name(left, source) else {
                    continue;
                };
                let unsafe_value = node
                    .child_by_field_name("right")
                    .is_some_and(|right| is_unsafe_rule(right, source));
                if unsafe_value {
                    unsafe_rules.insert(name);
                } else {
                    unsafe_rules.remove(name);
                }
            }
            "invocation_expression"
                if !is_error_tainted(node)
                    && matches!(
                        callee_name(node, source),
                        Some("AddAccessRule" | "SetAccessRule")
                    ) =>
            {
                let unsafe_argument = invocation_arguments(node).first().is_some_and(|argument| {
                    let value = argument_expression(*argument);
                    is_unsafe_rule(value, source)
                        || (value.kind() == "identifier"
                            && unsafe_rules.contains(node_text(value, source)))
                });
                if unsafe_argument {
                    issues.push(issue(
                        language,
                        "S2612",
                        "Make sure this permission is safe.",
                        range_of(node, source),
                    ));
                }
            }
            _ => {}
        }
    }
    issues
}

fn is_unsafe_rule(expression: Node<'_>, source: &str) -> bool {
    expression.kind() == "object_creation_expression"
        && expression
            .child_by_field_name("type")
            .is_some_and(|ty| simple_name(node_text(ty, source)) == "FileSystemAccessRule")
        && {
            let arguments = invocation_arguments(expression);
            let everyone = arguments.iter().any(|argument| {
                collect_kinds_in_callable(*argument, &["string_literal"])
                    .into_iter()
                    .any(|literal| literal_inner_text(literal, source) == "Everyone")
            });
            let allows = arguments.iter().any(|argument| {
                collect_kinds_in_callable(*argument, &["member_access_expression"])
                    .into_iter()
                    .any(|access| {
                        expression_name(access, source) == Some("Allow")
                            && access
                                .child_by_field_name("expression")
                                .is_some_and(|base| {
                                    simple_name(node_text(base, source)) == "AccessControlType"
                                })
                    })
            });
            everyone && allows
        }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2612_flags_allow_everyone_acl_sinks() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var unsafeRule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, AccessControlType.Allow);\n        var security = new FileSecurity();\n        security.AddAccessRule(unsafeRule);\n        security.SetAccessRule(unsafeRule);\n        security.ResetAccessRule(unsafeRule);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2612");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[1].range.start.line, 8);
    }

    #[test]
    fn s2612_spares_deny_everyone_acl_rules() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var safeRule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, AccessControlType.Deny);\n        var security = new FileSecurity();\n        security.AddAccessRule(safeRule);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2612").is_empty());
    }

    #[test]
    fn s2612_keeps_same_named_rules_in_separate_methods() {
        let report = analyze_default(
            "class C\n{\n    void BuildUnsafe()\n    {\n        var rule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, AccessControlType.Allow);\n    }\n\n    void InstallSafe(FileSecurity security)\n    {\n        var rule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, AccessControlType.Deny);\n        security.AddAccessRule(rule);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2612").is_empty());
    }

    #[test]
    fn s2612_tracks_reassignment_and_inline_rules_in_order() {
        let report = analyze_default(
            "class C\n{\n    void M(FileSecurity security)\n    {\n        var rule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.Read, AccessControlType.Deny);\n        security.AddAccessRule(rule);\n        rule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, AccessControlType.Allow);\n        security.AddAccessRule(rule);\n        security.SetAccessRule(new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, AccessControlType.Allow));\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2612").len(), 2);
    }

    #[test]
    fn s2612_requires_the_access_control_allow_enum() {
        let report = analyze_default(
            "class C\n{\n    void M(FileSecurity security)\n    {\n        var rule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, Other.Allow);\n        security.AddAccessRule(rule);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2612").is_empty());
    }
}
