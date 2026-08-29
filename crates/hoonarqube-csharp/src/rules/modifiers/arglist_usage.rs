use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4061 — `params` replaced `__arglist` long ago.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let uses_arglist = collect_kinds(method, &["identifier"])
            .into_iter()
            .any(|identifier| node_text(identifier, source) == "__arglist");
        if uses_arglist {
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S4061",
                "Use the 'params' keyword instead of '__arglist'.",
                range_of(name, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4061_ignores_arglist_text_in_comments_and_strings() {
        let report = analyze_default(
            "class C\n{\n    string M()\n    {\n        // __arglist is obsolete\n        return \"__arglist\";\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4061").is_empty());
    }
}
