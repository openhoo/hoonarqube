use super::support::{body_of, collect_kinds_in_callable};
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1048 — finalizers do not throw.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for destructor in collect_kinds(root, &["destructor_declaration"]) {
        if is_error_tainted(destructor) {
            continue;
        }
        let Some(body) = body_of(destructor) else {
            continue;
        };
        if let Some(throw_statement) = collect_kinds_in_callable(body, &["throw_statement"])
            .into_iter()
            .next()
        {
            issues.push(issue(
                language,
                "S1048",
                "Remove this 'throw' statement.",
                range_of(throw_statement, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1048_ignores_throws_inside_lambda_created_by_finalizer() {
        let report = analyze_default(
            "class C\n{\n    ~C()\n    {\n        System.Action callback = () => { throw new System.Exception(); };\n        callback();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1048").is_empty());
    }
}
