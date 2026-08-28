use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::integer_literal_value;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3937 — digit separators in number literals must form regular
/// groups.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["integer_literal"])
        .into_iter()
        .filter(|literal| !is_error_tainted(*literal))
        .filter(|literal| {
            let text = node_text(*literal, source);
            integer_literal_value(text).is_some()
                && text.contains('_')
                && text.split('_').skip(1).any(|group| group.len() != 3)
        })
        .map(|literal| {
            issue(
                language,
                "S3937",
                "Review this number; its irregular pattern indicates an error.",
                range_of(literal, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3937_keeps_short_regular_and_mixed_chains_clean() {
        let report = analyze_default(
            "class A\n{\n    void M(int code, int other)\n    {\n        if (code == 1 || code == 7) { }\n        if (code == 1 || code == 3 || code == 5 || code == 7) { }\n        if (code == 1 || other == 2 || code == 9) { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3937").is_empty());
    }

    #[test]
    fn s3937_reports_irregular_digit_groups_at_distinct_lines() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var first = 100_0;\n        var second = 100_00;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3937");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5); // document line 4
        assert_eq!(flagged[1].range.start.line, 6); // document line 5
    }

    #[test]
    fn s3937_minimal_body_without_or_chains_is_clean() {
        let report = analyze_default(
            "class A\n{\n    void M(int code)\n    {\n        if (code == 1) { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3937").is_empty());
    }

    #[test]
    fn s3937_accepts_regular_binary_literal_groups() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var bits = 0b101_010_101;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3937").is_empty());
    }
}
