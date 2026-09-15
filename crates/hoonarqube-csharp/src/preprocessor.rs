//! Preprocessor-directive parser views (#328).
//!
//! Real C# treats a preprocessor directive as line-scoped trivia in any
//! position, but the tree-sitter grammar cannot place one inside an
//! expression, so an `#if` interleaved between the tokens of a call's
//! argument list fails the whole file.  Recovery builds deterministic
//! parser views over the original bytes; byte lengths are preserved, so
//! every node range of a recovered tree still indexes the original source:
//!
//! 1. blank recognized directive lines, which recovers trivia-shaped
//!    placements while keeping both conditional branches visible;
//! 2. additionally evaluate the conditional branches with an
//!    undefined-symbol default — the same view a compiler without
//!    `/define` sees — so mutually exclusive `#else` bodies stay
//!    well-formed when blanking would merge them into invalid syntax.
//!
//! Views are withheld when the directive structure is unbalanced, keeping
//! genuinely broken input fail-closed.  Clean parses never reach recovery,
//! so files the grammar already accepts keep their ordinary tree including
//! every `preproc_*` node.

use std::borrow::Cow;
use std::collections::HashSet;

/// Parser views tried when the direct parse of a snapshot failed, in
/// application order.  Views identical to the source are omitted.
pub(crate) fn recovery_views(source: &str) -> Vec<Cow<'_, str>> {
    let mut views = Vec::new();
    if has_balanced_directives(source) {
        if let Cow::Owned(text) = blank_directive_lines(source) {
            views.push(Cow::Owned(text));
        }
        if let Some(text) = selected_branch_view(source) {
            views.push(Cow::Owned(text));
        }
    }
    views
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectiveKeyword {
    If,
    Elif,
    Else,
    Endif,
    Define,
    Undef,
    /// Directives that are trivia in every view (`#pragma`, `#region`, ...).
    Other,
}

#[derive(Debug, Clone, Copy)]
struct Directive<'a> {
    keyword: DirectiveKeyword,
    expression: &'a str,
}

/// Classifies one line's content (without its terminator) as a recognized
/// preprocessor directive.  Unrecognized `#`-prefixed lines stay untouched
/// so malformed input keeps failing closed.
fn directive_of(content: &str) -> Option<Directive<'_>> {
    let rest = content.trim_start().strip_prefix('#')?;
    let end = rest
        .find(|character: char| !character.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    let expression = rest[end..].trim();
    let keyword = match &rest[..end] {
        "if" => DirectiveKeyword::If,
        "elif" => DirectiveKeyword::Elif,
        "else" => DirectiveKeyword::Else,
        "endif" => DirectiveKeyword::Endif,
        "define" => DirectiveKeyword::Define,
        "undef" => DirectiveKeyword::Undef,
        "warning" | "error" | "line" | "nullable" | "pragma" | "region" | "endregion" => {
            DirectiveKeyword::Other
        }
        _ => return None,
    };
    Some(Directive {
        keyword,
        expression,
    })
}

fn split_terminator(line: &str) -> (&str, &str) {
    match line.strip_suffix('\n') {
        Some(rest) => match rest.strip_suffix('\r') {
            Some(content) => (content, "\r\n"),
            None => (rest, "\n"),
        },
        None => (line, ""),
    }
}

/// Recognized directives must nest properly (`#if`/`#endif`, no stray
/// `#else`/`#elif`/`#endif`) before any recovery view may be built.
fn has_balanced_directives(source: &str) -> bool {
    let mut depth = 0usize;
    for line in source.split_inclusive('\n') {
        let (content, _) = split_terminator(line);
        match directive_of(content).map(|directive| directive.keyword) {
            Some(DirectiveKeyword::If) => depth += 1,
            Some(DirectiveKeyword::Endif) => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            Some(DirectiveKeyword::Elif | DirectiveKeyword::Else) if depth == 0 => return false,
            _ => {}
        }
    }
    depth == 0
}

/// Byte-length-preserving view with every recognized directive line
/// blanked.
fn blank_directive_lines(source: &str) -> Cow<'_, str> {
    let mut normalized: Option<String> = None;
    let mut segment_start = 0;
    let mut cursor = 0;
    for line in source.split_inclusive('\n') {
        cursor += line.len();
        let (content, terminator) = split_terminator(line);
        if directive_of(content).is_none() {
            continue;
        }
        let output = normalized.get_or_insert_with(|| String::with_capacity(source.len()));
        output.push_str(&source[segment_start..cursor - line.len()]);
        output.extend(std::iter::repeat_n(' ', content.len()));
        output.push_str(terminator);
        segment_start = cursor;
    }
    match normalized {
        Some(mut output) => {
            output.push_str(&source[segment_start..]);
            Cow::Owned(output)
        }
        None => Cow::Borrowed(source),
    }
}

struct BranchFrame {
    parent_included: bool,
    any_branch_taken: bool,
    include: bool,
}

/// Evaluates the conditional branches with an undefined-symbol default and
/// blanks every excluded or directive line, returning the view a compiler
/// without `/define` sees.  `None` keeps the source when the directive
/// structure is unbalanced.
fn selected_branch_view(source: &str) -> Option<String> {
    let mut output: Option<String> = None;
    let mut segment_start = 0;
    let mut cursor = 0;
    let mut frames: Vec<BranchFrame> = Vec::new();
    let mut defines: HashSet<String> = HashSet::new();
    for line in source.split_inclusive('\n') {
        cursor += line.len();
        let (content, _terminator) = split_terminator(line);
        let included = frames.last().is_none_or(|frame| frame.include);
        if let Some(directive) = directive_of(content) {
            apply_directive(&mut frames, &mut defines, directive, included)?;
            blanked_output(&mut output, source, segment_start, cursor, line.len());
            segment_start = cursor;
        } else if !included {
            blanked_output(&mut output, source, segment_start, cursor, line.len());
            segment_start = cursor;
        }
    }
    if !frames.is_empty() {
        return None;
    }
    let mut text = output?;
    text.push_str(&source[segment_start..]);
    Some(text)
}

/// Starts a rebuilt view by copying the untouched bytes before the line and
/// blanking the line's content, keeping every byte offset stable.
fn blanked_output<'a>(
    output: &'a mut Option<String>,
    source: &str,
    segment_start: usize,
    cursor: usize,
    line_length: usize,
) -> &'a mut String {
    let output = output.get_or_insert_with(|| String::with_capacity(source.len()));
    output.push_str(&source[segment_start..cursor - line_length]);
    output.extend(std::iter::repeat_n(' ', line_length));
    output
}

fn apply_directive(
    frames: &mut Vec<BranchFrame>,
    defines: &mut HashSet<String>,
    directive: Directive<'_>,
    included: bool,
) -> Option<()> {
    match directive.keyword {
        DirectiveKeyword::If => {
            let include = included
                && !directive.expression.is_empty()
                && evaluate(directive.expression, defines);
            frames.push(BranchFrame {
                parent_included: included,
                any_branch_taken: include,
                include,
            });
        }
        DirectiveKeyword::Elif => {
            let frame = frames.last_mut()?;
            if frame.any_branch_taken {
                frame.include = false;
            } else {
                let include = frame.parent_included
                    && !directive.expression.is_empty()
                    && evaluate(directive.expression, defines);
                frame.any_branch_taken = include;
                frame.include = include;
            }
        }
        DirectiveKeyword::Else => {
            let frame = frames.last_mut()?;
            frame.include = frame.parent_included && !frame.any_branch_taken;
            frame.any_branch_taken |= frame.include;
        }
        DirectiveKeyword::Endif => {
            frames.pop()?;
        }
        DirectiveKeyword::Define => {
            if included && let Some(symbol) = symbol_name(directive.expression) {
                defines.insert(symbol.to_owned());
            }
        }
        DirectiveKeyword::Undef => {
            if included && let Some(symbol) = symbol_name(directive.expression) {
                defines.remove(symbol);
            }
        }
        DirectiveKeyword::Other => {}
    }
    Some(())
}

fn symbol_name(expression: &str) -> Option<&str> {
    let name = expression.split_whitespace().next()?;
    let mut characters = name.chars();
    let first = characters.next()?;
    if (first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        Some(name)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpressionToken {
    Not,
    And,
    Or,
    Equal,
    NotEqual,
    Open,
    Close,
    True,
    False,
    Symbol(String),
    Unknown,
}

fn tokenize(expression: &str) -> Vec<ExpressionToken> {
    let mut tokens = Vec::new();
    let mut characters = expression.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' => {}
            '(' => tokens.push(ExpressionToken::Open),
            ')' => tokens.push(ExpressionToken::Close),
            '!' => tokens.push(pair_operator(
                &mut characters,
                '=',
                ExpressionToken::NotEqual,
                ExpressionToken::Not,
            )),
            '&' => tokens.push(pair_operator(
                &mut characters,
                '&',
                ExpressionToken::And,
                ExpressionToken::Unknown,
            )),
            '|' => tokens.push(pair_operator(
                &mut characters,
                '|',
                ExpressionToken::Or,
                ExpressionToken::Unknown,
            )),
            '=' => tokens.push(pair_operator(
                &mut characters,
                '=',
                ExpressionToken::Equal,
                ExpressionToken::Unknown,
            )),
            character if character.is_ascii_alphabetic() || character == '_' => {
                tokens.push(word_token(&mut characters, character));
            }
            _ => tokens.push(ExpressionToken::Unknown),
        }
    }
    tokens
}

fn pair_operator(
    characters: &mut std::iter::Peekable<std::str::Chars<'_>>,
    second: char,
    combined: ExpressionToken,
    single: ExpressionToken,
) -> ExpressionToken {
    if characters.peek() == Some(&second) {
        characters.next();
        combined
    } else {
        single
    }
}

fn word_token(
    characters: &mut std::iter::Peekable<std::str::Chars<'_>>,
    first: char,
) -> ExpressionToken {
    let mut word = String::new();
    word.push(first);
    while let Some(&next) = characters.peek() {
        if next.is_ascii_alphanumeric() || next == '_' {
            word.push(next);
            characters.next();
        } else {
            break;
        }
    }
    match word.as_str() {
        "true" => ExpressionToken::True,
        "false" => ExpressionToken::False,
        _ => ExpressionToken::Symbol(word),
    }
}

/// Evaluates a C# preprocessor expression where every undefined symbol is
/// false — the same truth a compilation without `/define` observes.
/// Malformed expressions evaluate to `false`.
fn evaluate(expression: &str, defines: &HashSet<String>) -> bool {
    let tokens = tokenize(expression);
    let mut position = 0;
    match parse_or(&tokens, &mut position, defines) {
        Some(value) => position == tokens.len() && value,
        None => false,
    }
}

fn parse_or(
    tokens: &[ExpressionToken],
    position: &mut usize,
    defines: &HashSet<String>,
) -> Option<bool> {
    let mut value = parse_and(tokens, position, defines)?;
    while matches!(tokens.get(*position), Some(ExpressionToken::Or)) {
        *position += 1;
        value |= parse_and(tokens, position, defines)?;
    }
    Some(value)
}

fn parse_and(
    tokens: &[ExpressionToken],
    position: &mut usize,
    defines: &HashSet<String>,
) -> Option<bool> {
    let mut value = parse_equality(tokens, position, defines)?;
    while matches!(tokens.get(*position), Some(ExpressionToken::And)) {
        *position += 1;
        value &= parse_equality(tokens, position, defines)?;
    }
    Some(value)
}

fn parse_equality(
    tokens: &[ExpressionToken],
    position: &mut usize,
    defines: &HashSet<String>,
) -> Option<bool> {
    let mut value = parse_unary(tokens, position, defines)?;
    while matches!(
        tokens.get(*position),
        Some(ExpressionToken::Equal | ExpressionToken::NotEqual)
    ) {
        let equal = tokens[*position] == ExpressionToken::Equal;
        *position += 1;
        let right = parse_unary(tokens, position, defines)?;
        value = if equal {
            value == right
        } else {
            value != right
        };
    }
    Some(value)
}

fn parse_unary(
    tokens: &[ExpressionToken],
    position: &mut usize,
    defines: &HashSet<String>,
) -> Option<bool> {
    match tokens.get(*position) {
        Some(ExpressionToken::Not) => {
            *position += 1;
            Some(!parse_unary(tokens, position, defines)?)
        }
        Some(_) => parse_primary(tokens, position, defines),
        None => None,
    }
}

fn parse_primary(
    tokens: &[ExpressionToken],
    position: &mut usize,
    defines: &HashSet<String>,
) -> Option<bool> {
    match tokens.get(*position)? {
        ExpressionToken::Open => {
            *position += 1;
            let value = parse_or(tokens, position, defines)?;
            if tokens.get(*position) != Some(&ExpressionToken::Close) {
                return None;
            }
            *position += 1;
            Some(value)
        }
        ExpressionToken::True => {
            *position += 1;
            Some(true)
        }
        ExpressionToken::False => {
            *position += 1;
            Some(false)
        }
        ExpressionToken::Symbol(name) => {
            *position += 1;
            Some(defines.contains(name))
        }
        _ => None,
    }
}
