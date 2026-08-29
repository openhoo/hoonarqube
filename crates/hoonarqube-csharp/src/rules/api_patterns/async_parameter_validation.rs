use super::support::{collect_kinds_in_callable, validation_statements};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4457 — async methods should reject bad input before the
/// first suspension point; validations after an `await` surface late.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        if collect_kinds_in_callable(body, &["await_expression"]).is_empty()
            || validation_statements(body, source).is_empty()
        {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4457",
            "Split this method into two, one handling parameters check and the other handling the asynchronous code.",
            range_of(name, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4457_does_not_borrow_awaits_or_validation_from_local_functions() {
        let report = analyze_default(
            "class C\n{\n    async Task Outer(string value)\n    {\n        ArgumentNullException.ThrowIfNull(value);\n        async Task Local()\n        {\n            await SendAsync();\n        }\n    }\n\n    async Task Other()\n    {\n        await SendAsync();\n        void Validate()\n        {\n            ArgumentNullException.ThrowIfNull(\"value\");\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4457").is_empty());
    }
}
