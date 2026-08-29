use super::support::enclosing_type;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3236 — caller-information arguments are supplied by the
/// compiler and must not be spelled out at call sites.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let parameters = parameters_of(method);
        let supplied_by_compiler = parameters
            .iter()
            .filter(|parameter| {
                has_any_attribute(**parameter, source, &CALLER_INFORMATION_ATTRIBUTES)
            })
            .count();
        if supplied_by_compiler == 0 || supplied_by_compiler >= parameters.len() {
            continue;
        }
        let expected = parameters.len() - supplied_by_compiler;
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let Some(owner) = enclosing_type(method) else {
            continue;
        };
        let method_name = node_text(name, source);
        let overloaded = collect_kinds(owner, &["method_declaration"])
            .into_iter()
            .filter(|candidate| enclosing_type(*candidate) == Some(owner))
            .filter_map(|candidate| candidate.child_by_field_name("name"))
            .filter(|candidate| node_text(*candidate, source) == method_name)
            .count()
            > 1;
        if overloaded {
            continue;
        }
        for invocation in collect_kinds(root, &["invocation_expression"]) {
            if callee_name(invocation, source) != Some(method_name)
                || !invocation_may_target_owner(invocation, owner, source)
            {
                continue;
            }
            let arguments = invocation_arguments(invocation);
            if arguments.len() <= expected {
                continue;
            }
            issues.extend(arguments[expected..].iter().map(|argument| {
                issue(
                    language,
                    "S3236",
                    "Remove this argument from the method call; it hides the caller information.",
                    range_of(*argument, source),
                )
            }));
        }
    }
    issues
}

fn invocation_may_target_owner(invocation: Node<'_>, owner: Node<'_>, source: &str) -> bool {
    if enclosing_type(invocation) == Some(owner) {
        return true;
    }
    let Some(function) = invocation.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "member_access_expression" {
        return false;
    }
    let Some(owner_name) = owner.child_by_field_name("name") else {
        return false;
    };
    let mut cursor = function.walk();
    function
        .children(&mut cursor)
        .find(tree_sitter::Node::is_named)
        .is_some_and(|receiver| {
            receiver.kind() == "identifier"
                && node_text(receiver, source) == node_text(owner_name, source)
        })
}

/// Attributes whose arguments the compiler fills in automatically.
const CALLER_INFORMATION_ATTRIBUTES: [&str; 3] = [
    "CallerFilePath",
    "CallerLineNumber",
    "CallerArgumentExpression",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3236_does_not_match_same_named_methods_in_unrelated_types() {
        let report = analyze_default(
            "class A\n{\n    void Log(string message, [System.Runtime.CompilerServices.CallerLineNumber] int line = 0) { }\n}\n\nclass B\n{\n    void Log(string message, int code) { }\n    void Run() { Log(\"x\", 42); }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3236").is_empty());
    }

    #[test]
    fn s3236_skips_ambiguous_overloads() {
        let report = analyze_default(
            "class A\n{\n    void Log(string message, [System.Runtime.CompilerServices.CallerLineNumber] int line = 0) { }\n    void Log(string message, int code, int detail) { }\n    void Run() { Log(\"x\", 42); }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3236").is_empty());
    }
}
