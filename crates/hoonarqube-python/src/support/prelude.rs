// --- pre-section shared items

use ruff_python_ast::ModModule;
use ruff_python_ast::PySourceType;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_python_parser::parse_unchecked_source;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

pub(crate) fn parse(source: &str) -> Parsed<ModModule> {
    parse_unchecked_source(source, PySourceType::Python)
}

pub(crate) use hoonarqube_ir::u32_saturating as to_u32;

pub(crate) fn to_pos(offset: TextSize, index: &LineIndex, source: &str) -> hoonarqube_ir::Pos {
    let location = index.line_column(offset, source);
    hoonarqube_ir::Pos {
        line: to_u32(location.line.get()),
        column: to_u32(location.column.to_zero_indexed()),
    }
}

pub(crate) fn to_range(range: TextRange, index: &LineIndex, source: &str) -> hoonarqube_ir::Range {
    hoonarqube_ir::Range {
        start: to_pos(range.start(), index, source),
        end: to_pos(range.end(), index, source),
    }
}

pub(crate) use hoonarqube_ir::sort_issues;

/// Lines whose byte interval intersects `range`; multi-line tokens such as
/// triple-quoted strings legitimately span several lines.
fn covered_lines<'a>(
    range: TextRange,
    index: &'a LineIndex,
    source: &'a str,
) -> impl Iterator<Item = u32> + 'a {
    let first = to_u32(
        index
            .line_column(range.start(), source)
            .line
            .to_zero_indexed(),
    );
    let slice = &source[range];
    // A newline transitions to the next line only when characters follow it
    // inside the range; a token ending exactly at a newline stays on its line.
    let mut extra = to_u32(slice.matches('\n').count());
    if slice.ends_with('\n') && extra > 0 {
        extra -= 1;
    }
    first..=first + extra
}

pub(crate) fn file_metrics(
    parsed: &Parsed<ModModule>,
    source: &str,
    index: &LineIndex,
) -> hoonarqube_ir::FileMetrics {
    // File-size reports include the empty terminal row, unlike content
    // iterators. LineIndex already recognizes LF, CRLF, and bare CR.
    let lines = to_u32(index.line_count());
    let mut docstrings = std::collections::BTreeSet::new();
    let mut imports = Vec::new();
    collect_docstring_lines(
        parsed.syntax().body.as_slice(),
        index,
        source,
        &mut docstrings,
    );
    crate::support::for_each_stmt(parsed.syntax().body.as_slice(), &mut |statement| {
        let body = match statement {
            ruff_python_ast::Stmt::FunctionDef(function) => &function.body,
            ruff_python_ast::Stmt::ClassDef(class) => &class.body,
            ruff_python_ast::Stmt::Import(_) | ruff_python_ast::Stmt::ImportFrom(_) => {
                imports.push(statement.range());
                return;
            }
            _ => return,
        };
        collect_docstring_lines(body, index, source, &mut docstrings);
    });

    // Sonar's import AST does not expose comma/parenthesis delimiters.
    // Their rows and attached trivia therefore do not enter file metrics.
    imports.sort_unstable_by_key(Ranged::start);
    let mut import_index = 0;
    let mut import_delimiters = std::collections::HashSet::new();
    for token in parsed.tokens() {
        while imports
            .get(import_index)
            .is_some_and(|range| range.end() <= token.start())
        {
            import_index += 1;
        }
        if matches!(
            token.kind(),
            TokenKind::Lpar | TokenKind::Rpar | TokenKind::Comma
        ) && imports
            .get(import_index)
            .is_some_and(|range| range.contains_range(token.range()))
        {
            import_delimiters.insert(token.range());
        }
    }

    let code_lines: std::collections::BTreeSet<u32> = parsed
        .tokens()
        .iter()
        .filter(|token| {
            !token.kind().is_trivia()
                && !matches!(
                    token.kind(),
                    TokenKind::Newline
                        | TokenKind::Indent
                        | TokenKind::Dedent
                        | TokenKind::EndOfFile
                )
        })
        .filter(|token| !import_delimiters.contains(&token.range()))
        .flat_map(|token| covered_lines(token.range(), index, source))
        .filter(|line| !docstrings.contains(line))
        .collect();

    // Comments coexist with code on the same line. Punctuation-only
    // separators and NOSONAR directives are excluded by SonarPython.
    let mut comment_lines = std::collections::BTreeSet::new();
    let mut next_token = None;
    for token in parsed.tokens().iter().rev() {
        match token.kind() {
            TokenKind::Comment => {
                let text = &source[token.range()];
                let visible = next_token.is_some_and(|(kind, range)| {
                    kind != TokenKind::EndOfFile && !import_delimiters.contains(&range)
                });
                if visible && !text.contains("NOSONAR") && text.chars().any(char::is_alphanumeric) {
                    comment_lines.extend(covered_lines(token.range(), index, source));
                }
            }
            // Python grammar trivia is attached to the next real token;
            // synthetic scope markers are not comment attachment sites.
            TokenKind::NonLogicalNewline | TokenKind::Indent | TokenKind::Dedent => {}
            kind => next_token = Some((kind, token.range())),
        }
    }
    comment_lines.extend(docstrings);

    hoonarqube_ir::FileMetrics {
        lines,
        code_lines: to_u32(code_lines.len()),
        comment_lines: to_u32(comment_lines.len()),
    }
}

/// Only the first string expression in a module, class or function suite
/// is a docstring. Implicitly concatenated strings contribute their own
/// token rows; surrounding parentheses keep their code-line semantics.
fn collect_docstring_lines(
    body: &[ruff_python_ast::Stmt],
    index: &LineIndex,
    source: &str,
    lines: &mut std::collections::BTreeSet<u32>,
) {
    let Some(ruff_python_ast::Stmt::Expr(statement)) = body.first() else {
        return;
    };
    let ruff_python_ast::Expr::StringLiteral(literal) = statement.value.as_ref() else {
        return;
    };
    // Sonar's extractor requires a direct STRING_LITERAL statement;
    // parenthesized expressions remain code even when Python exposes __doc__.
    if statement.start() != literal.start() {
        return;
    }
    for part in &literal.value {
        lines.extend(covered_lines(part.range(), index, source));
    }
}

/// Iterates `(1-based line number, line text without terminators)`.
pub(crate) fn for_each_line(source: &str, mut visit: impl FnMut(u32, &str)) {
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let text = chunk.trim_end_matches(['\r', '\n']);
        visit(to_u32(zero_based) + 1, text);
    }
}

pub(crate) fn comment_tokens(
    parsed: &Parsed<ModModule>,
) -> impl Iterator<Item = &ruff_python_ast::token::Token> {
    parsed
        .tokens()
        .iter()
        .filter(|token| token.kind() == TokenKind::Comment)
}

pub(crate) const FIXME_TAG: &str = "fixme";

pub(crate) const TODO_TAG: &str = "todo";

/// Checks the text following a TODO/FIXME tag for the person reference
/// pattern `[ ]*\([ _a-zA-Z0-9@.]+\)` — e.g. `(jane)`. Sonar applies it
/// with unanchored `find()`, so any parenthesized group anywhere in the
/// tail exempts the comment.
pub(crate) fn has_person_reference(text_after_tag: &str) -> bool {
    let mut rest = text_after_tag;
    while let Some(open) = rest.find('(') {
        let after_open = &rest[open + 1..];
        let Some((body, _)) = after_open.split_once(')') else {
            return false;
        };
        if !body.is_empty()
            && body
                .chars()
                .all(|c| c == '_' || c == ' ' || c == '@' || c == '.' || c.is_ascii_alphanumeric())
        {
            return true;
        }
        rest = after_open;
    }
    false
}

/// Matches `([a-z_][a-z0-9_]*)|([A-Z][a-zA-Z0-9]+)` without a regex engine.
pub(crate) fn module_name_matches_convention(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first == '_' || first.is_ascii_lowercase() {
        name.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    } else {
        first.is_ascii_uppercase()
            && name.chars().skip(1).all(|c| c.is_ascii_alphanumeric())
            && name.len() > 1
    }
}
