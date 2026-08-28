use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, walk_all};
use crate::rules::expressions::{binary_operands, invocation_function};
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3366 — constructors must not publish `this` early.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for constructor in collect_kinds(root, &["constructor_declaration"]) {
        if is_error_tainted(constructor) {
            continue;
        }
        let Some(body) = body_of(constructor) else {
            continue;
        };
        let mut this_sites: Vec<Node> = Vec::new();
        walk_all(body, &mut |node| {
            if matches!(node.kind(), "this" | "this_expression") {
                this_sites.push(node);
            }
        });
        for this_expression in this_sites {
            let Some(parent) = this_expression.parent() else {
                continue;
            };
            let escapes = match parent.kind() {
                "argument" => parent
                    .parent()
                    .filter(|arguments| arguments.kind() == "argument_list")
                    .and_then(|node| node.parent())
                    .and_then(invocation_function)
                    .is_some_and(|function| function.kind() == "member_access_expression"),
                "return_statement" => true,
                "assignment_expression" => binary_operands(parent)
                    .is_some_and(|(_, right)| right.id() == this_expression.id()),
                _ => false,
            };
            if escapes {
                issues.push(issue(
                    language,
                    "S3366",
                    "Make sure the use of 'this' doesn't expose partially-constructed instances of this class in multi-threaded environments.",
                    range_of(this_expression, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3366_flags_returning_this_from_nested_block() {
        let report = analyze_default(
            "class C\n{\n    public C()\n    {\n        System.Func<C> factory = () =>\n        {\n            return this;\n        };\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3366");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s3366_ignores_this_as_assignment_target_qualifier() {
        let report = analyze_default(
            "class C\n{\n    private string name;\n\n    public C()\n    {\n        this.name = \"sample\";\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3366").is_empty());
    }

    #[test]
    fn s3366_ignores_constructor_without_this() {
        let report = analyze_default("class C\n{\n    public C()\n    {\n    }\n}\n");
        assert!(with_key(&report, "csharpsquid:S3366").is_empty());
    }

    #[test]
    fn s3366_reports_calls_on_other_objects_only() {
        let report = analyze_default(
            "class C\n{\n    public C()\n    {\n        System.Console.WriteLine(this);\n        Helper(this);\n    }\n\n    private void Helper(C other) { }\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S3366")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![5]);
    }
}
