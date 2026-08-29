use crate::CsLanguage;
use crate::cst::{issue, range_from_byte_offsets, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3972 — `else`, `catch`, and `finally` start on a new line.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "if_statement" {
            return;
        }
        let start = node.start_byte();
        let line_start = source[..start].rfind('\n').map_or(0, |offset| offset + 1);
        if source[line_start..start].trim_end().ends_with('}') {
            issues.push(issue(
                language,
                "S3972",
                "Move this 'if' to a new line or add the missing 'else'.",
                range_from_byte_offsets(start, start + 2, source),
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3972_uses_syntax_nodes_and_accepts_any_whitespace() {
        let report = analyze_default(
            "class C\n{\n    string text = \"} if this is prose\";\n    void M(bool first, bool second)\n    {\n        if (first) { }\tif (second) { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3972");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }
}
