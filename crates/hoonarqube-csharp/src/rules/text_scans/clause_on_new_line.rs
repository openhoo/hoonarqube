use crate::CsLanguage;
use crate::cst::{issue, range_from_byte_offsets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3972 — `else`, `catch`, and `finally` start on a new line.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let _ = root;
    let mut issues = Vec::new();
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        let line_without_comment = line.split_once("//").map_or(line, |(code, _)| code);
        let mut search_from = 0;
        while let Some(relative) = line_without_comment[search_from..].find("} if") {
            let start = offset + search_from + relative + 2;
            issues.push(issue(
                language,
                "S3972",
                "Move this 'if' to a new line or add the missing 'else'.",
                range_from_byte_offsets(start, start + 2, source),
            ));
            search_from += relative + 4;
        }
        offset += line.len();
    }
    issues
}
