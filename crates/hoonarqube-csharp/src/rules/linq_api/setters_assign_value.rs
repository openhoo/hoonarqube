use super::support::child_operator;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::accessor_keyword;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3237 — setters exist to consume `value`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for accessor in collect_kinds(root, &["accessor_declaration"]) {
        if accessor_keyword(accessor, source) != "set" {
            continue;
        }
        let Some(body) = accessor.child_by_field_name("body") else {
            continue;
        };
        let ignores_value =
            collect_kinds(body, &["assignment_expression"])
                .iter()
                .any(|assignment| {
                    child_operator(*assignment, source) == Some("=")
                        && binary_operands(*assignment).is_some_and(|(target, value)| {
                            target.kind() == "identifier"
                                && node_text(target, source) != "value"
                                && value.kind() == "identifier"
                                && node_text(value, source) != "value"
                                && node_text(value, source) != node_text(target, source)
                        })
                });
        if ignores_value {
            let set_keyword = collect_kinds(accessor, &["set"])
                .into_iter()
                .next()
                .unwrap_or(accessor);
            issues.push(issue(
                language,
                "S3237",
                "Use the 'value' contextual keyword in this property set accessor declaration.",
                range_of(set_keyword, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3237_flags_only_setters_that_ignore_value() {
        let report = analyze_default(
            "class E\n{\n    int cached;\n    int Compound { set { cached += value; } }\n    int Self { set { cached = cached; } }\n    int Sink { set { other = value; } }\n    int Ignored { get { return cached; } }\n    int Broken { set { cached = backup; } }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3237");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 8); // document line 7
    }

    #[test]
    fn s3237_minimal_class_without_accessors_is_clean() {
        let report = analyze_default("class E\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3237").is_empty());
    }
}
