use crate::support::comment_tokens;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::{ModModule, Stmt};
use ruff_python_parser::{Parsed, parse_module};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// ---------------------------------------------------------------------------
// python:S125 — commented-out code.
//
// The reference implementation groups consecutive comment lines, de-comments
// them, and parses the text as one Python program: a syntax error means the
// block is prose (ASCII art, Sphinx `#:` fields, sentences), and a parse that
// yields a single plain expression statement (or annotated assignment) is not
// code either. Only groups that parse as a multi-statement program — or that
// start with a non-expression statement such as `import`/`def`/assignments —
// report. This reproduces that semantics with the ruff parser instead of the
// old per-line token heuristic that flagged prose and annotation blocks.
// ---------------------------------------------------------------------------

/// The frozen catalog declares parameter `exception = "(fmt|py\w+):.*"` for
/// python:S125. Custom values are not surfaced through `AnalyzerOptions`, so
/// the default shape is pinned here: de-commented lines whose full text is
/// `fmt:`/`py<word>:` tool markers are excluded from the parse text, as are
/// the reference's Databricks magic commands.
fn is_exception_value(value: &str) -> bool {
    let trimmed = value.trim_start_matches([' ', '\t']);
    if trimmed.starts_with("MAGIC") || trimmed.starts_with("COMMAND") {
        return true;
    }
    let Some((marker, _)) = value.split_once(':') else {
        return false;
    };
    // mypy/pyright trailing directives (`# type: ignore[...]`,
    // `# pyright: ignore[...]`) are tool markers, not commented-out code:
    // they de-comment to AnnAssign-shaped lines that would otherwise slip
    // past the parse gate when consecutive lines form one group.
    if matches!(marker, "type" | "pyright") {
        return true;
    }
    marker == "fmt"
        || (marker.starts_with("py")
            && marker.len() > 2
            && marker[2..]
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'))
}

/// The reference's `SINGLE_WORD_PATTERN`: a full match of
/// `\s*[\w/\-]+\s*#*\n*` — one bare word, optionally followed by blanks and
/// `#`s — never reaches the parse text.
fn is_one_word(value: &str) -> bool {
    let rest = value.trim_start();
    let word_end = rest
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '/' || ch == '-'))
        .unwrap_or(rest.len());
    if word_end == 0 {
        return false;
    }
    rest[word_end..].trim_start().chars().all(|ch| ch == '#')
}

/// Mirrors the reference de-commenting: strip leading `#`s (and the blanks
/// ahead of an inner `#`), then one following blank; single-line groups are
/// trimmed whole.
fn decomment(raw: &str, single_line_group: bool) -> &str {
    let mut value = raw;
    loop {
        if let Some(rest) = value.strip_prefix('#') {
            value = rest;
        } else if value.starts_with(" #") {
            value = &value[1..];
        } else {
            break;
        }
    }
    if let Some(rest) = value.strip_prefix(' ') {
        value = rest;
    }
    if single_line_group {
        value.trim()
    } else {
        value
    }
}

/// PEP 263 coding declarations on the first two lines are excluded even when
/// they would parse (`# coding=utf8` is a valid assignment).
fn is_encoding_declaration(text: &str) -> bool {
    let Some(line) = text.strip_suffix('\n') else {
        return false;
    };
    if line.contains('\n') {
        return false;
    }
    for marker in ["coding:", "coding="] {
        if let Some(position) = line.find(marker) {
            let name = line[position + marker.len()..].trim_start_matches([' ', '\t']);
            if !name.is_empty()
                && name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            {
                return true;
            }
        }
    }
    false
}

/// Whether the de-commented group text parses as a real program under the
/// same rule the reference applies: any syntax error is prose, and a lone
/// expression statement (or annotated assignment) is not commented-out code.
fn parses_as_code(text: &str) -> bool {
    let Ok(parsed) = parse_module(text) else {
        return false;
    };
    if !parsed.errors().is_empty() {
        return false;
    }
    match parsed.syntax().body.as_slice() {
        [] => false,
        [only] => !matches!(only, Stmt::Expr(_) | Stmt::AnnAssign(_)),
        _ => true,
    }
}

fn group_reports(group: &[(usize, &str)]) -> bool {
    let single_line_group = group.len() == 1;
    let mut text = String::new();
    for &(_, raw) in group {
        let value = decomment(raw, single_line_group);
        if is_one_word(value) || is_exception_value(value) {
            continue;
        }
        text.push_str(value);
        text.push('\n');
    }
    if text.trim().is_empty() {
        return false;
    }
    if group[0].0 < 3 && is_encoding_declaration(&text) {
        return false;
    }
    parses_as_code(&text)
}

fn evaluate_group(
    group: &[(usize, &str)],
    anchor: Option<TextRange>,
    index: &LineIndex,
    source: &str,
) -> Option<Issue> {
    if !group_reports(group) {
        return None;
    }
    Some(Issue {
        rule_key: "python:S125".to_string(),
        message: "Remove this commented out code.".to_string(),
        range: to_range(anchor?, index, source),
        fix: None,
        flows: Vec::new(),
        alternatives: Vec::new(),
    })
}

pub(crate) fn check_commented_code(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut group: Vec<(usize, &str)> = Vec::new();
    let mut anchor: Option<TextRange> = None;
    let mut previous_line: usize = 0;
    let mut previous_had_code = false;
    for token in comment_tokens(parsed) {
        let line = index.line_column(token.range().start(), source).line.get();
        // The reference groups only consecutive comment lines attached to
        // the same following token: a comment on a line that already holds
        // code always starts a fresh group, so trailing comments on
        // consecutive code lines never merge into one program.
        let offset = usize::from(token.range().start());
        let line_start = source[..offset].rfind('\n').map_or(0, |pos| pos + 1);
        let has_code_before = !source[line_start..offset].trim().is_empty();
        // A comment-only line continues the group only when the previous
        // comment was also comment-only (both attach to the same following
        // token). A comment after code is always a singleton group.
        let continues = previous_line + 1 == line && !has_code_before && !previous_had_code;
        if !group.is_empty() && !continues {
            if let Some(issue) = evaluate_group(&group, anchor, index, source) {
                issues.push(issue);
            }
            group.clear();
        }
        if group.is_empty() {
            anchor = Some(token.range());
        }
        group.push((line, &source[token.range()]));
        previous_line = line;
        previous_had_code = has_code_before;
    }
    if let Some(issue) = evaluate_group(&group, anchor, index, source) {
        issues.push(issue);
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
    }

    #[test]
    fn s125_spares_ascii_art_and_sphinx_field_annotations() {
        // ASCII-art logo blocks (requests `__init__.py`) never parse as Python.
        let art = scan(concat!(
            "#  _______  __   __  _______  __    _  _______\n",
            "# |   _   ||  | |  ||       ||  |  | ||       |\n",
            "# |  |_|  ||  |_|  ||    ___||   |_| ||    ___|\n",
        ));
        assert!(findings(&art, "python:S125").is_empty());

        // Sphinx '#:' doc-field annotations above attributes.
        let sphinx = scan(concat!(
            "class S:\n",
            "    def __init__(self):\n",
            "        #: Dictionary mapping protocol to the URL of the proxy\n",
            "        #: (e.g. {'http': 'foo.bar:3128'}) used on each request.\n",
            "        self.proxies = {}\n",
        ));
        assert!(findings(&sphinx, "python:S125").is_empty());
    }

    #[test]
    fn s125_requires_the_whole_comment_group_to_parse_like_sonar() {
        // Sonar de-comments a group of consecutive comment lines and parses
        // the text as one program; prose lines make the group unparseable,
        // so a line that looks like disabled code beside prose stays clean.
        let mixed = scan(concat!(
            "# The next statement was disabled during debugging:\n",
            "# value = compute(1)\n",
        ));
        assert!(findings(&mixed, "python:S125").is_empty());

        // Multi-line prose sentence blocks never parse as Python.
        let prose = scan(concat!(
            "# In general, we want to try IDNA encoding the hostname if the string contains\n",
            "# non-ASCII characters. This allows users to get the correct IDNA behaviour.\n",
        ));
        assert!(findings(&prose, "python:S125").is_empty());
    }
}
