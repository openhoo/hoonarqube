use super::support::{collect_kinds_in_callable, validation_statements};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4456 — iterators defer their whole body until
/// enumeration, so argument validation inside them surfaces far from
/// the buggy call site.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some(body) = body_of(method) else {
            continue;
        };
        if collect_kinds_in_callable(body, &["yield_statement"]).is_empty() {
            continue;
        }
        if !validation_statements(body, source).is_empty() {
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S4456",
                "Split this method into two, one handling parameters check and the other handling the iterator.",
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
    fn s4456_does_not_borrow_validation_from_a_local_function() {
        let report = analyze_default(
            "class C\n{\n    IEnumerable<int> Values(int[] values)\n    {\n        void Validate()\n        {\n            ArgumentNullException.ThrowIfNull(values);\n        }\n        yield return values.Length;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4456").is_empty());
    }
}
