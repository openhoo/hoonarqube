use super::support::enclosing_callable;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1121 — assignments belong in dedicated statements.
/// Object-initializer members are initializer syntax, not embedded
/// assignments.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) {
            continue;
        }
        let parent_kind = assignment.parent().map(|parent| parent.kind());
        if matches!(
            parent_kind,
            Some("expression_statement" | "for_statement" | "initializer_expression")
        ) || inside_if_condition(assignment)
        {
            continue;
        }
        let target = assignment
            .child_by_field_name("left")
            .map_or("value", |left| node_text(left, source));
        let anchor = collect_kinds(assignment, &["="])
            .into_iter()
            .next()
            .unwrap_or(assignment);
        issues.push(issue(
            language,
            "S1121",
            format!("Extract the assignment of '{target}' from this expression."),
            range_of(anchor, source),
        ));
    }
    issues
}

fn inside_if_condition(assignment: Node<'_>) -> bool {
    let mut ancestor = assignment.parent();
    while let Some(node) = ancestor {
        if node.kind() == "if_statement" {
            return enclosing_callable(assignment).map(|owner| owner.id())
                == enclosing_callable(node).map(|owner| owner.id())
                && node
                    .child_by_field_name("condition")
                    .is_some_and(|condition| {
                        assignment.start_byte() >= condition.start_byte()
                            && assignment.end_byte() <= condition.end_byte()
                    });
        }
        ancestor = node.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1121_flags_embedded_assignments_but_not_dedicated_statements() {
        let bad = analyze_default("class C { bool M() { int value; return (value = 1) > 0; } }");
        assert_eq!(with_key(&bad, "csharpsquid:S1121").len(), 1);

        let good = analyze_default("class C { void M() { int value; value = 1; } }");
        assert!(with_key(&good, "csharpsquid:S1121").is_empty());
    }

    #[test]
    fn s1121_if_condition_exception_does_not_cross_lambda_scope() {
        let report = analyze_default(
            "class C { bool M(int[] items) { int value; if (items.Any(_ => (value = 1) > 0)) return true; return false; } }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1121").len(), 1);
    }

    #[test]
    fn s1121_object_initializer_members_are_not_embedded_assignments() {
        // Issue #242: Dapper DynamicParameters — initializer members use
        // initializer syntax, not assignments embedded in a statement's
        // expression.
        let initializer = analyze_default(
            "class C {\n    object M(string name, object value, System.Collections.Generic.Dictionary<string, object> map) {\n\
                 var info = new Param\n                {\n\
                     Name = name,\n\
                     Value = value\n\
                 };\n\
                 map[\"key\"] = new Param\n                {\n\
                     Name = name\n\
                 };\n\
                 return info;\n\
             }\n}\n",
        );
        assert!(with_key(&initializer, "csharpsquid:S1121").is_empty());

        // Control: an assignment genuinely embedded in an expression still
        // reports.
        let embedded =
            analyze_default("class C { bool M() { int value; return (value = 1) > 0; } }");
        assert_eq!(with_key(&embedded, "csharpsquid:S1121").len(), 1);
    }
}
