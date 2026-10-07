//! Validate the legacy constructs handled by our Python 2 detectors without
//! treating every recovered Ruff tree as complete source. This translation is
//! used only as a syntax check; metrics always inspect the original parse.

use ruff_python_ast::{ModModule, token::TokenKind};
use ruff_python_parser::Parsed;
use ruff_text_size::Ranged;

use super::{parse, unmasked_segments};
use crate::rules::py2_statements::is_statement_form;

pub(crate) fn has_valid_legacy_syntax(parsed: &Parsed<ModModule>, source: &str) -> bool {
    let Some((translated, mut changed)) = translate_legacy_operators(parsed, source) else {
        return false;
    };
    let legacy_parse = parse(&translated);
    let tokens = legacy_parse.tokens();
    let mut edits = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        if token.kind() != TokenKind::Name {
            continue;
        }
        let keyword = &translated[token.range()];
        if !matches!(keyword, "print" | "exec") {
            continue;
        }
        let start = usize::from(token.start());
        if !is_statement_form(&translated, start, keyword, keyword == "print") {
            continue;
        }
        let mut end = translated.len();
        let mut depth = 0usize;
        let mut operands = Vec::new();
        for next in tokens.iter().skip(i + 1) {
            let kind = next.kind();
            if depth == 0
                && matches!(
                    kind,
                    TokenKind::Newline
                        | TokenKind::Semi
                        | TokenKind::Comment
                        | TokenKind::EndOfFile
                )
            {
                end = usize::from(next.start());
                break;
            }
            match kind {
                TokenKind::Lpar | TokenKind::Lsqb | TokenKind::Lbrace => depth += 1,
                TokenKind::Rpar | TokenKind::Rsqb | TokenKind::Rbrace => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
            if !kind.is_trivia() {
                operands.push(next);
            }
        }
        if operands.is_empty() {
            // Bare print is valid, bare exec is not a statement form.
            continue;
        }
        // Python 2 operands are tests, not unpacking or a bare generator.
        // Nested calls/comprehensions retain ordinary expression grammar.
        let mut nested = 0usize;
        let mut seen_in = false;
        let mut scope_commas = 0usize;
        for (position, operand) in operands.iter().enumerate() {
            match operand.kind() {
                TokenKind::Lpar | TokenKind::Lsqb | TokenKind::Lbrace => nested += 1,
                TokenKind::Rpar | TokenKind::Rsqb | TokenKind::Rbrace => {
                    nested = nested.saturating_sub(1);
                }
                TokenKind::In if nested == 0 => seen_in = true,
                TokenKind::For | TokenKind::Async if nested == 0 => return false,
                TokenKind::Star | TokenKind::DoubleStar if nested == 0 => {
                    if position == 0 || operands[position - 1].kind() == TokenKind::Comma {
                        return false;
                    }
                }
                TokenKind::Comma if nested == 0 && keyword == "exec" => {
                    // exec accepts an expression, then at most two scopes.
                    scope_commas += 1;
                    if !seen_in || scope_commas > 1 {
                        return false;
                    }
                }
                _ => {}
            }
        }
        // A tuple expression accepts print's comma-separated operands and
        // keeps nested call syntax (and its parser errors) intact.
        edits.push((start, usize::from(token.end()), "("));
        edits.push((end, end, ")"));
        if keyword == "print" && operands[0].kind() == TokenKind::RightShift {
            edits.push((
                usize::from(operands[0].start()),
                usize::from(operands[0].end()),
                "  ",
            ));
        }
        changed = true;
    }
    if !changed {
        return false;
    }
    let mut validated = translated;
    edits.sort_unstable_by_key(|(start, end, _)| (*start, *end));
    for (start, end, replacement) in edits.into_iter().rev() {
        validated.replace_range(start..end, replacement);
    }
    parse(&validated).errors().is_empty()
}

fn translate_legacy_operators(parsed: &Parsed<ModModule>, source: &str) -> Option<(String, bool)> {
    let mut translated = source.as_bytes().to_vec();
    let mut backtick = None;
    let mut changed = false;
    for (base, segment) in unmasked_segments(parsed, source) {
        for (relative, byte) in segment.bytes().enumerate() {
            let at = base + relative;
            if byte == b'`' {
                if let Some(open) = backtick.take() {
                    if source[open + 1..at].trim().is_empty() {
                        return None;
                    }
                    translated[open] = b'(';
                    translated[at] = b')';
                } else {
                    backtick = Some(at);
                }
                changed = true;
            } else if byte == b'<' && segment.as_bytes().get(relative + 1) == Some(&b'>') {
                translated[at] = b'!';
                translated[at + 1] = b'=';
                changed = true;
            }
        }
    }
    if backtick.is_some() {
        return None;
    }
    // ASCII replacements preserve UTF-8 and all source offsets.
    let translated = String::from_utf8(translated).ok()?;
    Some((translated, changed))
}
