//! Validate the legacy constructs handled by our Python 2 detectors without
//! treating every recovered Ruff tree as complete source. This translation is
//! used only as a syntax check; metrics always inspect the original parse.

use ruff_python_ast::{
    ModModule,
    token::{Token, TokenKind},
};
use ruff_python_parser::Parsed;
use ruff_text_size::Ranged;

use super::{parse, unmasked_segments};
use crate::rules::py2_statements::is_statement_form;

type ValidationEdit = (usize, usize, &'static str);

pub(crate) fn has_valid_legacy_syntax(parsed: &Parsed<ModModule>, source: &str) -> bool {
    let Some((translated, operators_changed)) = translate_legacy_operators(parsed, source) else {
        return false;
    };
    let Some(mut edits) = legacy_statement_edits(&translated) else {
        return false;
    };
    if !operators_changed && edits.is_empty() {
        return false;
    }
    let mut validated = translated;
    edits.sort_unstable_by_key(|(start, end, _)| (*start, *end));
    for (start, end, replacement) in edits.into_iter().rev() {
        validated.replace_range(start..end, replacement);
    }
    parse(&validated).errors().is_empty()
}

fn legacy_statement_edits(source: &str) -> Option<Vec<ValidationEdit>> {
    let parsed = parse(source);
    let tokens: Vec<&Token> = parsed.tokens().iter().collect();
    let mut edits = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let keyword = &source[token.range()];
        let start = usize::from(token.start());
        if token.kind() != TokenKind::Name || !matches!(keyword, "print" | "exec") {
            continue;
        }
        if !is_statement_form(source, start, keyword, keyword == "print") {
            continue;
        }
        let (end, operands) = statement_operands(&tokens[i + 1..], source.len());
        if operands.is_empty() {
            // Bare print is valid, bare exec is not a statement form.
            continue;
        }
        if !valid_legacy_operands(&operands, keyword) {
            return None;
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
    }
    Some(edits)
}

fn statement_operands<'a>(tokens: &[&'a Token], source_len: usize) -> (usize, Vec<&'a Token>) {
    let mut depth = 0usize;
    let mut operands = Vec::new();
    for token in tokens {
        let kind = token.kind();
        if depth == 0 && ends_statement(kind) {
            return (usize::from(token.start()), operands);
        }
        depth = bracket_depth(depth, kind);
        if !kind.is_trivia() {
            operands.push(*token);
        }
    }
    (source_len, operands)
}

fn ends_statement(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Newline | TokenKind::Semi | TokenKind::Comment | TokenKind::EndOfFile
    )
}

fn bracket_depth(depth: usize, kind: TokenKind) -> usize {
    match kind {
        TokenKind::Lpar | TokenKind::Lsqb | TokenKind::Lbrace => depth + 1,
        TokenKind::Rpar | TokenKind::Rsqb | TokenKind::Rbrace => depth.saturating_sub(1),
        _ => depth,
    }
}

fn valid_legacy_operands(operands: &[&Token], keyword: &str) -> bool {
    // Python 2 operands are tests, not unpacking or a bare generator.
    // Nested calls/comprehensions retain ordinary expression grammar.
    let mut depth = 0usize;
    let mut seen_in = false;
    let mut scope_commas = 0usize;
    for (position, operand) in operands.iter().enumerate() {
        let kind = operand.kind();
        depth = bracket_depth(depth, kind);
        if depth != 0 {
            continue;
        }
        if invalid_top_level_operand(operands, position) {
            return false;
        }
        if kind == TokenKind::In {
            seen_in = true;
        }
        if kind == TokenKind::Comma && keyword == "exec" {
            // exec accepts an expression, then at most two scopes.
            scope_commas += 1;
            if !seen_in || scope_commas > 1 {
                return false;
            }
        }
    }
    true
}

fn invalid_top_level_operand(operands: &[&Token], position: usize) -> bool {
    match operands[position].kind() {
        TokenKind::For | TokenKind::Async => true,
        TokenKind::Star | TokenKind::DoubleStar => {
            position == 0 || operands[position - 1].kind() == TokenKind::Comma
        }
        _ => false,
    }
}

fn translate_legacy_operators(parsed: &Parsed<ModModule>, source: &str) -> Option<(String, bool)> {
    let mut translated = source.as_bytes().to_vec();
    let mut backtick = None;
    let mut changed = false;
    for (base, segment) in unmasked_segments(parsed, source) {
        changed |=
            translate_operator_segment(source, segment, base, &mut translated, &mut backtick)?;
    }
    if backtick.is_some() {
        return None;
    }
    // ASCII replacements preserve UTF-8 and all source offsets.
    Some((String::from_utf8(translated).ok()?, changed))
}

fn translate_operator_segment(
    source: &str,
    segment: &str,
    base: usize,
    translated: &mut [u8],
    backtick: &mut Option<usize>,
) -> Option<bool> {
    let mut changed = false;
    for (relative, byte) in segment.bytes().enumerate() {
        let at = base + relative;
        match byte {
            b'`' => {
                translate_backtick(source, translated, backtick, at)?;
                changed = true;
            }
            b'<' if segment.as_bytes().get(relative + 1) == Some(&b'>') => {
                translated[at] = b'!';
                translated[at + 1] = b'=';
                changed = true;
            }
            _ => {}
        }
    }
    Some(changed)
}

fn translate_backtick(
    source: &str,
    translated: &mut [u8],
    backtick: &mut Option<usize>,
    at: usize,
) -> Option<()> {
    if let Some(open) = backtick.take() {
        if source[open + 1..at].trim().is_empty() {
            return None;
        }
        translated[open] = b'(';
        translated[at] = b')';
    } else {
        *backtick = Some(at);
    }
    Some(())
}
