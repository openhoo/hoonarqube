use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::declaration_contracts::enclosing_method;
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2302 — strings that mirror an enclosing parameter name
/// should travel through `nameof`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let inner = literal_inner_text(literal, source);
        if !is_identifier_text(inner) {
            continue;
        }
        let mirrors_parameter = enclosing_method(literal).is_some_and(|method| {
            parameters_of(method).iter().any(|parameter| {
                parameter
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == inner)
            })
        });
        if mirrors_parameter {
            issues.push(issue(
                language,
                "S2302",
                format!("Replace this string with 'nameof({inner})'."),
                range_of(literal),
            ));
        }
    }
    issues
}

/// Whether the text parses as a plain identifier usable with `nameof`.
fn is_identifier_text(text: &str) -> bool {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) if first.is_alphabetic() || first == '_' => {}
        _ => return false,
    }
    characters.all(|rest| rest.is_alphanumeric() || rest == '_')
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2302_requires_identifier_text_and_method_scope() {
        let report = analyze_default(
            "class A\n{\n    string tag = \"fallback\";\n\n    void Render(string label)\n    {\n        log(label + \":\");\n        Use(\"label with space\");\n        Use(\"1st\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2302").is_empty());
    }

    #[test]
    fn s2302_counts_every_match_but_respects_enclosing_parameters() {
        let report = analyze_default(
            "class A\n{\n    void Save(string userId)\n    {\n        audit(\"userId\");\n        audit(\"userId\");\n    }\n\n    void Send(string batch)\n    {\n        audit(\"batch\");\n        audit(\"userId\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2302");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
        assert_eq!(flagged[2].range.start.line, 11);
    }
}
