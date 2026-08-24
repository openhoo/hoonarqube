use super::support::identifier_write;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S127 — a `for` stop condition stays invariant: nothing in
/// the body may assign a name the condition tests. Update-clause writes
/// drive the loop and are exempt by design.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let Some(condition) = for_statement.child_by_field_name("condition") else {
            continue;
        };
        let condition_names: std::collections::HashSet<&str> =
            collect_kinds(condition, &["identifier"])
                .into_iter()
                .map(|identifier| node_text(identifier, source))
                .collect();
        let Some(body) = for_statement.child_by_field_name("body") else {
            continue;
        };
        let body_writes = written_names(body, source);
        if condition_names
            .iter()
            .any(|name| body_writes.contains(name))
        {
            issues.push(issue(
                language,
                "S127",
                "This loop's stop condition is not invariant.",
                range_of(for_statement),
            ));
        }
    }
    issues
}

/// Names receiving a write anywhere in the subtree: assignment targets,
/// increment operands, and declared names alike.
fn written_names<'a>(node: Node<'_>, source: &'a str) -> std::collections::HashSet<&'a str> {
    let mut names = std::collections::HashSet::new();
    walk_all(node, &mut |current| {
        if current.kind() == "identifier" && identifier_write(current).is_some() {
            names.insert(node_text(current, source));
        }
    });
    names
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S127";

    #[test]
    fn s127_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s127_literal_bound_loop_is_invariant() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (int i = 0; i < 10; i++) {\n            Tick(i);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s127_body_write_to_condition_name_flags() {
        let report = analyze_default(
            "class C {\n    void M(int top) {\n        for (int i = 0; i < top; i++) {\n            top = Read();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s127_body_increment_of_condition_name_flags() {
        let report = analyze_default(
            "class C {\n    void M(int top) {\n        for (int i = 0; i < top; i++) {\n            top++;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s127_update_clause_write_is_exempt_by_design() {
        let report = analyze_default(
            "class C {\n    void M(int top) {\n        for (int i = 0; i < top; i++, top--) {\n            Tick(i);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s127_unrelated_body_writes_stay_clean() {
        let report = analyze_default(
            "class C {\n    void M(int top) {\n        for (int i = 0; i < top; i++) {\n            int local;\n            local = Compute();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
