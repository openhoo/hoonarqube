use super::support::creation_type_text;
use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3717 — thrown `NotImplementedException`s are tracked so
/// unfinished work stays visible.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for throw_statement in collect_kinds(root, &["throw_statement"]) {
        if is_error_tainted(throw_statement) {
            continue;
        }
        let tracked = first_named_child(throw_statement).is_some_and(|thrown| {
            thrown.kind() == "object_creation_expression"
                && simple_name(creation_type_text(thrown, source)) == "NotImplementedException"
        });
        if tracked {
            issues.push(issue(
                language,
                "S3717",
                "Track uses of 'NotImplementedException'.",
                range_of(throw_statement),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3717_minimal_class_has_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3717").is_empty());
    }

    #[test]
    fn s3717_tracks_bare_and_qualified_not_implemented_throws() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        throw new NotImplementedException();\n        throw new System.NotImplementedException(\"later\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3717");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s3717_other_exceptions_and_rethrows_stay_untracked() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        throw new InvalidOperationException(\"busy\");\n        throw;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3717").is_empty());
    }
}
