use super::support::first_child_token_text;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::{
    block_statements, callee_name, first_named_child, invocation_function,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1185 — overrides that only forward to `base` add noise.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "override") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let statements = block_statements(body);
        if statements.len() != 1 {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let forwards = forwards_to_base(statements[0], node_text(name, source), source);
        if forwards {
            issues.push(issue(
                language,
                "S1185",
                format!(
                    "Remove this method '{}' to simply inherit its behavior.",
                    node_text(name, source)
                ),
                range_of(method, source),
            ));
        }
    }
    issues
}

/// Whether the single statement is a bare or returning `base.M(...)` call.
fn forwards_to_base(statement: Node<'_>, member: &str, source: &str) -> bool {
    let Some(inner) = first_named_child(statement) else {
        return false;
    };
    let invocation = match inner.kind() {
        "return_statement" => first_named_child(inner),
        "invocation_expression" => Some(inner),
        _ => None,
    };
    let Some(invocation) = invocation else {
        return false;
    };
    callee_name(invocation, source) == Some(member)
        && invocation_function(invocation).is_some_and(|function| {
            function.kind() == "member_access_expression"
                && first_child_token_text(function, source) == "base"
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1185_requires_override_and_same_member_forwarding() {
        let report = analyze_default(
            "class D : B\n{\n    public override string Name() { return base.Other(); }\n    public string Size() { return base.Size(); }\n    public override void Run() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1185").is_empty());
    }

    #[test]
    fn s1185_minimal_class_without_overrides_is_clean() {
        let report = analyze_default("class D : B\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1185").is_empty());
    }
}
