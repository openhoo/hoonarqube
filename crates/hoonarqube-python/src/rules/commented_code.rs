use crate::support::comment_tokens;
use crate::support::line_looks_like_code;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// ---------------------------------------------------------------------------
// python:S125 — commented-out code.
// ---------------------------------------------------------------------------

/// The frozen catalog declares parameter `exception = "(fmt|py\w+):.*"` for
/// python:S125. Custom values are not surfaced through `AnalyzerOptions`, so
/// the default shape is pinned here: comments whose text starts with `fmt:`
/// or `py<word>:` are tool markers, not commented-out code.
fn matches_catalog_exception(line: &str) -> bool {
    let content = line.trim_start();
    let Some(content) = content.strip_prefix('#') else {
        return false;
    };
    let content = content.trim_start();
    if content.starts_with("fmt:") {
        return true;
    }
    let Some(rest) = content.strip_prefix("py") else {
        return false;
    };
    let mut chars = rest.chars().peekable();
    let mut word_len = 0;
    while chars
        .peek()
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
    {
        chars.next();
        word_len += 1;
    }
    word_len > 0 && chars.next() == Some(':')
}

fn is_documentation_heading(line: &str) -> bool {
    const CODE_STARTERS: [&str; 10] = [
        "return", "if", "for", "while", "def", "class", "import", "from", "raise", "yield",
    ];
    let content = line.trim_start().strip_prefix('#').unwrap_or("").trim();
    let mut words = content.split_whitespace();
    let Some(title) = words.next() else {
        return false;
    };
    let Some(decoration) = words.next_back() else {
        return false;
    };
    !CODE_STARTERS.contains(&title)
        && title.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
        && decoration.len() >= 3
        && decoration.chars().all(|ch| ch == '-' || ch == '=')
        && words.all(|word| word.chars().all(|ch| ch.is_alphanumeric() || ch == '_'))
}

pub(crate) fn check_commented_code(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for token in comment_tokens(parsed) {
        let looks_like_code = source[token.range()]
            .lines()
            .filter(|line| !matches_catalog_exception(line))
            .filter(|line| !is_documentation_heading(line))
            .any(line_looks_like_code);
        if looks_like_code {
            issues.push(Issue {
                rule_key: "python:S125".to_string(),
                message: "Remove this commented out code.".to_string(),
                range: to_range(token.range(), index, source),
                fix: None,
                flows: Vec::new(),
                alternatives: Vec::new(),
            });
        }
    }
    issues
}
#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s125_spares_documentation_headings_but_flags_commented_code() {
        let headings = scan(
            "# Project --------------------------------------------------------------\n\
# General ---------------------------------------------------------------\n",
        );
        assert!(findings(&headings, "python:S125").is_empty());

        let disabled = scan("# value = compute(1)\n");
        assert_eq!(findings(&disabled, "python:S125").len(), 1);

        // A genuine disabled statement must remain visible even beside a
        // prose heading; this is not a blanket suppression of S125.
        let mixed = scan(
            "# Project --------------------------------------------------------------\n\
# value = compute(1)\n",
        );
        assert_eq!(findings(&mixed, "python:S125").len(), 1);
    }
}
