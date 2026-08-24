use super::support::block_statements;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::{else_alternative, embedded_bodies, is_else_alternative};
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3923 — every branch of a conditional runs the same code.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(header) || is_else_alternative(header) {
            continue;
        }
        let Some(texts) = if_chain_branch_texts(header, source) else {
            continue;
        };
        let identical = texts.len() >= 2
            && texts.iter().all(|text| !text.is_empty())
            && texts.windows(2).all(|pair| pair[0] == pair[1]);
        if identical {
            issues.push(issue(
                language,
                "S3923",
                "Every branch of this conditional performs the same actions.",
                range_of(header),
            ));
        }
    }
    issues
}

/// Statement text of a branch body; block wrappers are flattened so
/// `{ return 1; }` and `return 1;` compare equal.
fn branch_body_text(body: Node<'_>, source: &str) -> String {
    if body.kind() == "block" {
        block_statements(body)
            .iter()
            .map(|statement| node_text(*statement, source))
            .collect::<Vec<_>>()
            .concat()
    } else {
        node_text(body, source).to_string()
    }
}

/// Branch body texts of a complete if/else-if/else chain, or `None` when the
/// chain lacks a terminal `else` (incomplete coverage).
fn if_chain_branch_texts(header: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut texts = Vec::new();
    let mut current = Some(header);
    while let Some(if_statement) = current {
        let consequence = *embedded_bodies(if_statement).first()?;
        texts.push(branch_body_text(consequence, source));
        let alternative = else_alternative(if_statement)?;
        if alternative.kind() == "if_statement" {
            current = Some(alternative);
        } else {
            texts.push(branch_body_text(alternative, source));
            current = None;
        }
    }
    Some(texts)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3923_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3923").is_empty());
    }

    #[test]
    fn s3923_reports_fully_identical_three_way_chain_once() {
        let report = analyze_default(
            "class C\n{\n    void M(int n)\n    {\n        if (n == 1) { Run(); }\n        else if (n == 2) { Run(); }\n        else { Run(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3923");
        // Only the outermost header of a chain is reported: nested
        // `else if` headers are skipped via `is_else_alternative`, so the
        // fully identical three-way chain yields exactly one finding.
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[0].range.end.line, 7);
    }
    #[test]
    fn s3923_incomplete_chains_without_else_never_flag() {
        let report = analyze_default(
            "class C\n{\n    void M(bool a)\n    {\n        if (a) { Run(); }\n        if (a) { Run(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3923").is_empty());
    }

    #[test]
    fn s3923_multiline_identical_blocks_flag_but_ternary_does_not() {
        let report = analyze_default(
            "class C\n{\n    int M(bool c)\n    {\n        if (c)\n        {\n            return 1;\n        }\n        else\n        {\n            return 1;\n        }\n    }\n}\n\nclass D\n{\n    int M(bool c)\n    {\n        return c ? Same() : Same();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3923");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3923_near_miss_bodies_do_not_flag() {
        let report = analyze_default(
            "class C\n{\n    void M(bool c)\n    {\n        if (c) { Run(1); }\n        else { Run(2); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3923").is_empty());
    }

    #[test]
    fn s3923_reports_two_independent_chains_at_their_headers() {
        let report = analyze_default(
            "class C\n{\n    void M(bool a, bool b)\n    {\n        if (a) { Go(); }\n        else { Go(); }\n\n        if (b) { Halt(); }\n        else { Halt(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3923");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 8);
    }
}
