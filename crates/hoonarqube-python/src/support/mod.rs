use crate::AnalyzerOptions;
use crate::context::FlowState;
use crate::context::context_is_async;
use crate::context::for_each_call_in_fn_context;
use crate::engine::calls::concrete_hint;
use crate::engine::calls::hint_accepts_literal;
use crate::engine::rx::RxParsed;
use crate::engine::rx::RxUnit;
use crate::engine::scope::RaiseContext;
use crate::engine::scope::SuiteOwner;
use crate::rules::rx_repetition_hazards::check_rx_repetition_hazards;
use crate::rules::rx_style_shapes::check_rx_style_shapes;
use crate::rules::rx_syntax_shapes::check_rx_syntax_shapes;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::PySourceType;
use ruff_python_ast::Stmt;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_python_parser::parse_unchecked_source;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;
use std::collections::HashMap;
use std::collections::HashSet;

pub(crate) fn parse(source: &str) -> Parsed<ModModule> {
    parse_unchecked_source(source, PySourceType::Python)
}

pub(crate) fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

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

pub(crate) fn sort_issues(issues: &mut [Issue]) {
    issues.sort_by(|a, b| {
        (
            a.range.start.line,
            a.range.start.column,
            a.range.end.line,
            a.range.end.column,
            a.rule_key.as_str(),
            a.message.as_str(),
        )
            .cmp(&(
                b.range.start.line,
                b.range.start.column,
                b.range.end.line,
                b.range.end.column,
                b.rule_key.as_str(),
                b.message.as_str(),
            ))
    });
}

/// Lines whose byte interval intersects `range`; multi-line tokens such as
/// triple-quoted strings legitimately span several lines.
pub(crate) fn covered_lines<'a>(
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
    let lines = if source.is_empty() {
        0
    } else {
        to_u32(source.lines().count())
    };

    let code_lines: std::collections::BTreeSet<u32> = parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia())
        .flat_map(|token| covered_lines(token.range(), index, source))
        .collect();

    let comment_lines: std::collections::BTreeSet<u32> = parsed
        .tokens()
        .iter()
        .filter(|token| token.kind().is_comment())
        .flat_map(|token| covered_lines(token.range(), index, source))
        .filter(|line| !code_lines.contains(line))
        .collect();

    hoonarqube_ir::FileMetrics {
        lines,
        code_lines: to_u32(code_lines.len()),
        comment_lines: to_u32(comment_lines.len()),
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

/// Checks the first TODO/FIXME occurrence in the comment for the person
/// reference pattern `[ ]*\([ _a-zA-Z0-9@.]+\)`.
pub(crate) fn has_person_reference(lowercased_comment: &str) -> bool {
    let Some(tag_pos) = lowercased_comment
        .find(FIXME_TAG)
        .into_iter()
        .chain(lowercased_comment.find(TODO_TAG))
        .min()
    else {
        return true;
    };
    let rest = lowercased_comment[tag_pos..]
        .trim_start_matches(|c: char| c.is_ascii_alphabetic())
        .trim_start_matches(' ');
    let Some(body) = rest.strip_prefix('(').and_then(|r| r.split_once(')')) else {
        return false;
    };
    !body.0.is_empty()
        && body
            .0
            .chars()
            .all(|c| c == '_' || c == ' ' || c == '@' || c == '.' || c.is_ascii_alphanumeric())
}

/// Validates every `noqa` occurrence in the raw comment text against
/// `# noqa` / `# noqa: E501[,F841]`.
pub(crate) fn noqa_format_valid(text: &str) -> bool {
    let lower = text.to_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find("noqa") {
        let start = search_from + rel;
        let before = &text[..start];
        let hash_ok = match before.rfind('#') {
            Some(hash_pos) => {
                let gap = &before[hash_pos + 1..];
                !gap.is_empty() && gap.chars().all(|c| c == ' ')
            }
            None => false,
        };
        if !hash_ok {
            return false;
        }
        let after = &text[start + 4..];
        if !(after.is_empty() || after.starts_with('#')) {
            let Some(codes) = after.strip_prefix(':') else {
                return false;
            };
            for code in codes.split(',') {
                let code = code.trim();
                let valid = !code.is_empty()
                    && code
                        .chars()
                        .all(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && code.chars().any(|c: char| c.is_ascii_uppercase())
                    && code
                        .find(|c: char| c.is_ascii_digit())
                        .is_some_and(|first_digit| {
                            code[..first_digit]
                                .chars()
                                .all(|c: char| c.is_ascii_uppercase())
                        });
                if !valid {
                    return false;
                }
            }
        }
        search_from = start + 4;
    }
    true
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

// ---------------------------------------------------------------------------
// Shared helpers for the Tier-A rule battery.
// ---------------------------------------------------------------------------

pub(crate) const PYTHON_KEYWORDS: [&str; 35] = [
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

pub(crate) fn is_keyword(text: &str) -> bool {
    PYTHON_KEYWORDS.contains(&text)
}

/// Directly nested statement bodies of a compound statement.
pub(crate) fn child_bodies(stmt: &Stmt) -> Vec<&[Stmt]> {
    match stmt {
        Stmt::FunctionDef(s) => vec![s.body.as_slice()],
        Stmt::ClassDef(s) => vec![s.body.as_slice()],
        Stmt::For(s) => vec![s.body.as_slice(), s.orelse.as_slice()],
        Stmt::While(s) => vec![s.body.as_slice(), s.orelse.as_slice()],
        Stmt::If(s) => {
            let mut bodies = vec![s.body.as_slice()];
            bodies.extend(
                s.elif_else_clauses
                    .iter()
                    .map(|clause| clause.body.as_slice()),
            );
            bodies
        }
        Stmt::With(s) => vec![s.body.as_slice()],
        Stmt::Match(s) => s.cases.iter().map(|case| case.body.as_slice()).collect(),
        Stmt::Try(s) => {
            let mut bodies = vec![
                s.body.as_slice(),
                s.orelse.as_slice(),
                s.finalbody.as_slice(),
            ];
            bodies.extend(s.handlers.iter().map(|handler| match handler {
                ExceptHandler::ExceptHandler(handler) => handler.body.as_slice(),
            }));
            bodies
        }
        _ => Vec::new(),
    }
}

/// Depth-first visit of every statement in the tree.
pub(crate) fn for_each_stmt(stmts: &[Stmt], visit: &mut impl FnMut(&Stmt)) {
    for stmt in stmts {
        visit(stmt);
        for body in child_bodies(stmt) {
            for_each_stmt(body, visit);
        }
    }
}

/// Direct child expressions of an expression. FString/TString interiors are
/// intentionally opaque: their literal parts are not visited.
pub(crate) fn child_exprs(expr: &Expr) -> Vec<&Expr> {
    let mut children: Vec<&Expr> = Vec::new();
    match expr {
        Expr::BoolOp(e) => children.extend(&e.values),
        Expr::Named(e) => {
            children.push(&e.target);
            children.push(&e.value);
        }
        Expr::BinOp(e) => {
            children.push(&e.left);
            children.push(&e.right);
        }
        Expr::UnaryOp(e) => children.push(&e.operand),
        Expr::Lambda(e) => children.push(&e.body),
        Expr::If(e) => {
            children.push(&e.test);
            children.push(&e.body);
            children.push(&e.orelse);
        }
        Expr::Dict(e) => {
            for item in &e.items {
                if let Some(key) = &item.key {
                    children.push(key);
                }
                children.push(&item.value);
            }
        }
        Expr::Set(e) => children.extend(&e.elts),
        Expr::List(e) => children.extend(&e.elts),
        Expr::Tuple(e) => children.extend(&e.elts),
        Expr::ListComp(e) => {
            children.push(&e.elt);
            push_generator_exprs(&e.generators, &mut children);
        }
        Expr::SetComp(e) => {
            children.push(&e.elt);
            push_generator_exprs(&e.generators, &mut children);
        }
        Expr::Generator(e) => {
            children.push(&e.elt);
            push_generator_exprs(&e.generators, &mut children);
        }
        Expr::DictComp(e) => {
            if let Some(key) = &e.key {
                children.push(key);
            }
            children.push(&e.value);
            push_generator_exprs(&e.generators, &mut children);
        }
        Expr::Await(e) => children.push(&e.value),
        Expr::YieldFrom(e) => children.push(&e.value),
        Expr::Yield(e) => children.extend(e.value.as_deref()),
        Expr::Compare(e) => {
            children.push(&e.left);
            children.extend(&e.comparators);
        }
        Expr::Call(e) => {
            children.push(&e.func);
            children.extend(&e.arguments.args);
            children.extend(e.arguments.keywords.iter().map(|keyword| &keyword.value));
        }
        Expr::Attribute(e) => children.push(&e.value),
        Expr::Subscript(e) => {
            children.push(&e.value);
            children.push(&e.slice);
        }
        Expr::Starred(e) => children.push(&e.value),
        Expr::Slice(e) => {
            for bound in [&e.lower, &e.upper, &e.step].into_iter().flatten() {
                children.push(bound);
            }
        }
        _ => {}
    }
    children
}

pub(crate) fn push_generator_exprs<'a>(
    generators: &'a [ruff_python_ast::Comprehension],
    children: &mut Vec<&'a Expr>,
) {
    for generator in generators {
        children.push(&generator.target);
        children.push(&generator.iter);
        children.extend(&generator.ifs);
    }
}

pub(crate) fn for_each_expr(expr: &Expr, visit: &mut impl FnMut(&Expr)) {
    visit(expr);
    for child in child_exprs(expr) {
        for_each_expr(child, visit);
    }
}

/// Visits every expression reachable from a statement tree.
pub(crate) fn for_each_stmt_expr(stmts: &[Stmt], visit: &mut impl FnMut(&Expr)) {
    for_each_stmt(stmts, &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, visit);
        }
    });
}

/// Top-level expressions carried directly by a statement (decorators,
/// annotations, defaults, tests, targets, values, ...).
pub(crate) fn stmt_exprs(stmt: &Stmt) -> Vec<&Expr> {
    let mut exprs: Vec<&Expr> = Vec::new();
    match stmt {
        Stmt::FunctionDef(s) => {
            for decorator in &s.decorator_list {
                exprs.push(&decorator.expression);
            }
            if let Some(returns) = &s.returns {
                exprs.push(returns);
            }
            push_parameter_exprs(&s.parameters, &mut exprs);
        }
        Stmt::ClassDef(s) => {
            for decorator in &s.decorator_list {
                exprs.push(&decorator.expression);
            }
            if let Some(arguments) = &s.arguments {
                exprs.extend(&arguments.args);
                exprs.extend(arguments.keywords.iter().map(|keyword| &keyword.value));
            }
        }
        Stmt::Return(s) => exprs.extend(s.value.as_deref()),
        Stmt::Delete(s) => exprs.extend(&s.targets),
        Stmt::Assign(s) => {
            exprs.extend(&s.targets);
            exprs.push(&s.value);
        }
        Stmt::AugAssign(s) => {
            exprs.push(&s.target);
            exprs.push(&s.value);
        }
        Stmt::AnnAssign(s) => {
            exprs.push(&s.target);
            exprs.push(&s.annotation);
            exprs.extend(s.value.as_deref());
        }
        Stmt::For(s) => {
            exprs.push(&s.target);
            exprs.push(&s.iter);
        }
        Stmt::While(s) => exprs.push(&s.test),
        Stmt::If(s) => {
            exprs.push(&s.test);
            for clause in &s.elif_else_clauses {
                if let Some(test) = &clause.test {
                    exprs.push(test);
                }
            }
        }
        Stmt::With(s) => {
            for item in &s.items {
                exprs.push(&item.context_expr);
                if let Some(vars) = &item.optional_vars {
                    exprs.push(vars);
                }
            }
        }
        Stmt::Match(s) => {
            exprs.push(&s.subject);
            for case in &s.cases {
                if let Some(guard) = &case.guard {
                    exprs.push(guard);
                }
            }
        }
        Stmt::Raise(s) => {
            exprs.extend(s.exc.as_deref());
            exprs.extend(s.cause.as_deref());
        }
        Stmt::Assert(s) => exprs.push(&s.test),
        Stmt::Expr(s) => exprs.push(&s.value),
        _ => {}
    }
    exprs
}

/// Default values and annotations of a parameter list.
pub(crate) fn push_parameter_exprs<'a>(
    parameters: &'a ruff_python_ast::Parameters,
    exprs: &mut Vec<&'a Expr>,
) {
    for parameter in parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
    {
        if let Some(annotation) = parameter.parameter.annotation.as_deref() {
            exprs.push(annotation);
        }
        if let Some(default) = parameter.default.as_deref() {
            exprs.push(default);
        }
    }
    for bound in [parameters.vararg.as_deref(), parameters.kwarg.as_deref()]
        .into_iter()
        .flatten()
    {
        if let Some(annotation) = bound.annotation.as_deref() {
            exprs.push(annotation);
        }
    }
}

/// Decoded text and source span of every plain string literal in the tree.
/// Bytes literals and f-strings are intentionally not collected.
pub(crate) fn collect_string_contents(stmts: &[Stmt]) -> Vec<(String, TextRange)> {
    let mut contents = Vec::new();
    for_each_stmt_expr(stmts, &mut |expr| {
        if let Expr::StringLiteral(literal) = expr {
            contents.push((string_value_text(&literal.value), literal.range()));
        }
    });
    contents
}

/// Concatenated decoded text of a (possibly implicitly concatenated)
/// string literal value.
pub(crate) fn string_value_text(value: &ruff_python_ast::StringLiteralValue) -> String {
    let mut text = String::new();
    for part in value {
        text.push_str(&part.value);
    }
    text
}

pub(crate) fn shannon_entropy(text: &str) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in text.as_bytes() {
        counts[byte as usize] += 1;
    }
    let total = f64::from(to_u32(text.len()));
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = f64::from(*count) / total;
            -probability * probability.log2()
        })
        .sum()
}

/// Maximal runs of characters satisfying `predicate`.
pub(crate) fn maximal_runs<'a>(
    text: &'a str,
    predicate: impl Fn(char) -> bool + 'a,
) -> impl Iterator<Item = &'a str> + 'a {
    text.split(move |ch| !predicate(ch))
        .filter(|run| !run.is_empty())
}

pub(crate) fn significant_tokens(
    parsed: &Parsed<ModModule>,
) -> Vec<&ruff_python_ast::token::Token> {
    parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia())
        .collect()
}

/// Source regions that must be ignored by raw-text scans: comments, string
/// literals, and whole f-string/t-string regions including their interiors.
pub(crate) fn masked_spans(parsed: &Parsed<ModModule>) -> Vec<TextRange> {
    let mut spans = Vec::new();
    let mut depth = 0u32;
    let mut open_region: Option<TextSize> = None;
    for token in parsed.tokens() {
        match token.kind() {
            TokenKind::Comment | TokenKind::String => spans.push(token.range()),
            TokenKind::FStringStart | TokenKind::TStringStart => {
                depth += 1;
                if open_region.is_none() {
                    open_region = Some(token.range().start());
                }
            }
            TokenKind::FStringEnd | TokenKind::TStringEnd => {
                depth = depth.saturating_sub(1);
                if depth == 0
                    && let Some(start) = open_region.take()
                {
                    spans.push(TextRange::new(start, token.range().end()));
                }
            }
            _ => {}
        }
    }
    spans
}

/// `(absolute byte offset, text)` for the source outside all masked spans.
pub(crate) fn unmasked_segments<'a>(
    parsed: &'a Parsed<ModModule>,
    source: &'a str,
) -> Vec<(usize, &'a str)> {
    let mut spans = masked_spans(parsed);
    spans.sort_by_key(|range| (u32::from(range.start()), u32::from(range.end())));
    let mut segments = Vec::new();
    let mut cursor = 0usize;
    for range in spans {
        let start = usize::try_from(u32::from(range.start())).unwrap_or(0);
        let end = usize::try_from(u32::from(range.end())).unwrap_or(0);
        if start > cursor {
            segments.push((cursor, &source[cursor..start]));
        }
        cursor = cursor.max(end);
    }
    if cursor < source.len() {
        segments.push((cursor, &source[cursor..]));
    }
    segments
}

/// Extracts IPv4 and IPv6-looking candidates; loopback, wildcard, and
/// broadcast IPv4 addresses are exempt per the RSPEC.
pub(crate) fn ip_addresses(text: &str) -> Vec<String> {
    let mut found: Vec<String> = maximal_runs(text, |ch| ch.is_ascii_digit() || ch == '.')
        .filter_map(parse_ipv4)
        .collect();
    found.extend(
        maximal_runs(text, |ch| ch.is_ascii_hexdigit() || ch == ':').filter_map(parse_ipv6),
    );
    found.sort();
    found.dedup();
    found
}

pub(crate) fn parse_ipv4(run: &str) -> Option<String> {
    const EXEMPT: [&str; 3] = ["0.0.0.0", "127.0.0.1", "255.255.255.255"];
    let octets: Vec<&str> = run.split('.').collect();
    let valid = octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        });
    if valid && !EXEMPT.contains(&run) {
        Some(run.to_string())
    } else {
        None
    }
}

pub(crate) fn parse_ipv6(run: &str) -> Option<String> {
    if run == "::" || run == "::1" {
        return None;
    }
    let groups: Vec<&str> = run.split(':').filter(|group| !group.is_empty()).collect();
    let valid = groups.len() >= 3
        && groups
            .iter()
            .all(|group| group.len() <= 4 && group.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if valid { Some(run.to_string()) } else { None }
}

// ---------------------------------------------------------------------------
// python:S2068 — hard-coded credentials.
// ---------------------------------------------------------------------------

pub(crate) const CREDENTIAL_WORDS: [&str; 4] = ["password", "passwd", "pwd", "passphrase"];

pub(crate) fn name_words(name: &str) -> impl Iterator<Item = &str> {
    name.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
}

/// Matches `(?i)(password|passwd|pwd|passphrase)\s*[=:]\s*\S` inside a
/// string literal.
pub(crate) fn embeds_credential(text: &str) -> bool {
    let lower = text.to_lowercase();
    CREDENTIAL_WORDS.iter().any(|word| {
        lower.match_indices(word).any(|(position, _)| {
            let rest = lower[position + word.len()..].trim_start_matches([' ', '\t']);
            let Some(separator) = rest.chars().next() else {
                return false;
            };
            (separator == '=' || separator == ':')
                && rest[1..]
                    .trim_start_matches([' ', '\t'])
                    .chars()
                    .next()
                    .is_some_and(|ch| !ch.is_whitespace())
        })
    })
}

// ---------------------------------------------------------------------------
// python:S6418 / python:S6437 — hard-coded secrets.
// ---------------------------------------------------------------------------

pub(crate) const SECRET_ENTROPY_THRESHOLD: f64 = 3.0;

pub(crate) const SECRET_HIGH_ENTROPY_THRESHOLD: f64 = 4.5;

pub(crate) fn is_secret_name(name: &str) -> bool {
    let normalized: String = name
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    ["apikey", "auth", "credential", "secret", "token"]
        .iter()
        .any(|word| normalized.contains(word))
}

pub(crate) fn stmt_targets(stmt: &Stmt) -> impl Iterator<Item = &Expr> {
    match stmt {
        Stmt::Assign(s) => s.targets.iter().collect::<Vec<&Expr>>().into_iter(),
        Stmt::AnnAssign(s) => vec![&*s.target as &Expr].into_iter(),
        _ => Vec::new().into_iter(),
    }
}

pub(crate) fn line_looks_like_code(line: &str) -> bool {
    const STATEMENT_STARTERS: [&str; 7] =
        ["import", "from", "def", "class", "return", "raise", "del"];
    if line.starts_with("#!") {
        // Shebang: never commented-out code.
        return false;
    }
    let stripped = line.trim_start_matches('#').trim();
    if stripped.is_empty() {
        return false;
    }
    let words: Vec<&str> = stripped
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|word| !word.is_empty())
        .collect();
    if words
        .first()
        .is_some_and(|word| STATEMENT_STARTERS.contains(word))
    {
        return true;
    }
    let operators = stripped
        .chars()
        .filter(|ch| "()[]{}=:.<>+-*/%|&^~,".contains(*ch))
        .count();
    let keywords = words.iter().filter(|word| is_keyword(word)).count();
    (keywords >= 1 && operators >= 2) || operators >= 3
}

/// Whether a token can end an operand, which would turn an adjacent
/// same-sign pair into binary addition instead of a prefix operator.
pub(crate) fn ends_operand(token: &ruff_python_ast::token::Token, source: &str) -> bool {
    match token.kind() {
        TokenKind::Name => !is_keyword(&source[token.range()]),
        TokenKind::Int
        | TokenKind::Float
        | TokenKind::Complex
        | TokenKind::String
        | TokenKind::Rpar
        | TokenKind::Rsqb => true,
        _ => false,
    }
}

/// Byte offsets of backslashes introducing unrecognized escapes.
pub(crate) fn invalid_escape_offsets(raw: &str) -> Vec<usize> {
    let bytes = raw.as_bytes();
    let Some(quote_at) = bytes.iter().position(|&byte| byte == b'\'' || byte == b'"') else {
        return Vec::new();
    };
    let quote = bytes[quote_at];
    let triple = bytes[quote_at..].starts_with(&[quote, quote, quote]);
    let mut offsets = Vec::new();
    let mut i = quote_at + if triple { 3 } else { 1 };
    let end = raw.len().saturating_sub(if triple { 3 } else { 1 });
    while i < end {
        if bytes[i] == b'\\' {
            match bytes.get(i + 1) {
                None => break,
                Some(b'\n' | b'\r') => i += 2,
                Some(&next) if is_valid_escape_byte(next) => i += 2,
                Some(_) => {
                    offsets.push(i);
                    i += 2;
                }
            }
        } else {
            i += 1;
        }
    }
    offsets
}

pub(crate) fn is_valid_escape_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'\\'
            | b'\''
            | b'"'
            | b'a'
            | b'b'
            | b'f'
            | b'n'
            | b'r'
            | b't'
            | b'v'
            | b'x'
            | b'N'
            | b'u'
            | b'U'
    ) || byte.is_ascii_digit()
}

pub(crate) fn is_bytes_literal(raw: &str) -> bool {
    let prefix = raw
        .split(['"', '\''])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    prefix.contains('b')
}

// ---------------------------------------------------------------------------
// Tier-A battery entries #48–#110 (python:S2772 … python:S7512).
//
// One private check per catalog entry, wired through `check_tier_a_battery`.
// Detection follows the batch spec: single-file AST/token/text heuristics
// with deliberately conservative predicates.
// ---------------------------------------------------------------------------

/// Builds an issue anchored at `range`.
pub(crate) fn issue_at(
    rule_key: &str,
    message: &str,
    range: TextRange,
    index: &LineIndex,
    source: &str,
) -> Issue {
    Issue {
        rule_key: rule_key.to_string(),
        message: message.to_string(),
        range: to_range(range, index, source),
    }
}

/// Whitespace-normalized source text of `expr` (dedent-insensitive equality).
pub(crate) fn expr_normalized_text(expr: &Expr, source: &str) -> String {
    source[expr.range()]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn exprs_textually_equal(left: &Expr, right: &Expr, source: &str) -> bool {
    expr_normalized_text(left, source) == expr_normalized_text(right, source)
}

pub(crate) fn ranges_textually_equal(left: TextRange, right: TextRange, source: &str) -> bool {
    let normalize = |range: TextRange| -> String {
        source[range]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    normalize(left) == normalize(right)
}

/// Span covering a whole non-empty suite.
pub(crate) fn suite_span(suite: &[Stmt]) -> TextRange {
    TextRange::new(
        suite.first().expect("non-empty").range().start(),
        suite.last().expect("non-empty").range().end(),
    )
}

/// Whether a suite holds nothing but `pass`/`...` placeholders; docstrings
/// and every other statement count as content.
pub(crate) fn placeholder_only_suite(suite: &[Stmt]) -> bool {
    !suite.is_empty()
        && suite.iter().all(|stmt| match stmt {
            Stmt::Pass(_) => true,
            Stmt::Expr(expr) => matches!(expr.value.as_ref(), Expr::EllipsisLiteral(_)),
            _ => false,
        })
}

/// Callee name of a call shaped `name(...)` or `value.name(...)`.
pub(crate) fn called_name(func: &Expr) -> Option<&str> {
    match func {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    }
}

pub(crate) fn is_call_to(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Call(call) if called_name(&call.func) == Some(name))
}

/// Positional parameters (`posonlyargs` followed by regular `args`).
pub(crate) fn positional_parameters(
    parameters: &ruff_python_ast::Parameters,
) -> Vec<&ruff_python_ast::Parameter> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .map(|with_default| &with_default.parameter)
        .collect()
}

pub(crate) fn is_none_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::NoneLiteral(_))
}

pub(crate) fn is_zero_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::NumberLiteral(number)
            if matches!(&number.value, ruff_python_ast::Number::Int(value) if value.as_i64() == Some(0))
    )
}

pub(crate) fn collect_target_names(target: &Expr, names: &mut Vec<String>) {
    match target {
        Expr::Name(name) => names.push(name.id.to_string()),
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                collect_target_names(element, names);
            }
        }
        Expr::List(list) => {
            for element in &list.elts {
                collect_target_names(element, names);
            }
        }
        Expr::Starred(starred) => collect_target_names(&starred.value, names),
        _ => {}
    }
}

/// Whether any `break` lexically bound to a loop over `suite` exists. Breaks
/// inside nested loop bodies belong to the inner loop and do not count.
pub(crate) fn suite_can_break(suite: &[Stmt]) -> bool {
    suite.iter().any(|stmt| match stmt {
        Stmt::Break(_) => true,
        Stmt::For(inner) => suite_can_break(&inner.orelse),
        Stmt::While(inner) => suite_can_break(&inner.orelse),
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => false,
        _ => child_bodies(stmt).iter().any(|body| suite_can_break(body)),
    })
}

pub(crate) fn visit_ifexp_branches(
    expr: &Expr,
    in_branch: bool,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    match expr {
        Expr::If(nested) => {
            if in_branch {
                issues.push(issue_at(
                    "python:S3358",
                    "Refactor this conditional expression nested inside another into a statement.",
                    nested.range(),
                    index,
                    source,
                ));
            }
            visit_ifexp_branches(&nested.test, false, issues, index, source);
            visit_ifexp_branches(&nested.body, true, issues, index, source);
            visit_ifexp_branches(&nested.orelse, true, issues, index, source);
        }
        _ => {
            for child in child_exprs(expr) {
                visit_ifexp_branches(child, in_branch, issues, index, source);
            }
        }
    }
}

/// Whether `expr`'s subtree loads any of `names`.
pub(crate) fn loads_any_name(expr: &Expr, names: &[String]) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |node| {
        if let Expr::Name(name) = node
            && matches!(name.ctx, ruff_python_ast::ExprContext::Load)
        {
            found |= names.iter().any(|candidate| candidate == name.id.as_str());
        }
    });
    found
}

/// Whether `expr` contains a floating-point literal anywhere in its subtree.
pub(crate) fn contains_float_literal(expr: &Expr) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |node| {
        found |= matches!(
            node,
            Expr::NumberLiteral(number) if matches!(number.value, ruff_python_ast::Number::Float(_))
        );
    });
    found
}

/// Canonical grouping text for constant-foldable literal keys/elements.
pub(crate) fn constant_literal_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(literal) => Some(format!("s:{}", string_value_text(&literal.value))),
        Expr::BytesLiteral(literal) => {
            let bytes: Vec<u8> = literal
                .value
                .iter()
                .flat_map(|part| part.value.iter())
                .copied()
                .collect();
            Some(format!("b:{bytes:?}"))
        }
        Expr::NumberLiteral(literal) => Some(match &literal.value {
            ruff_python_ast::Number::Int(value) => match value.as_i64() {
                Some(small) => format!("i:{small}"),
                None => "i:large".to_string(),
            },
            ruff_python_ast::Number::Float(value) => format!("f:{value:?}"),
            ruff_python_ast::Number::Complex { real, imag } => format!("c:{real:?}{imag:?}"),
        }),
        Expr::BooleanLiteral(literal) => Some(format!("z:{}", literal.value)),
        Expr::NoneLiteral(_) => Some("n:".to_string()),
        Expr::Tuple(tuple) => {
            let parts: Option<Vec<String>> = tuple.elts.iter().map(constant_literal_text).collect();
            parts.map(|parts| format!("t:({})", parts.join(",")))
        }
        Expr::UnaryOp(unary) if unary.op == ruff_python_ast::UnaryOp::USub => {
            constant_literal_text(&unary.operand).map(|text| format!("-{text}"))
        }
        _ => None,
    }
}

/// Like [`for_each_stmt`] but does not descend into nested function or class
/// scopes.
pub(crate) fn for_each_stmt_in_scope(stmts: &[Stmt], visit: &mut impl FnMut(&Stmt)) {
    for stmt in stmts {
        visit(stmt);
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        for body in child_bodies(stmt) {
            for_each_stmt_in_scope(body, visit);
        }
    }
}

pub(crate) fn has_decorator(
    function: &ruff_python_ast::StmtFunctionDef,
    decorator_name: &str,
) -> bool {
    function
        .decorator_list
        .iter()
        .any(|decorator| match &decorator.expression {
            Expr::Name(name) => name.id.as_str() == decorator_name,
            Expr::Attribute(attribute) => attribute.attr.as_str() == decorator_name,
            _ => false,
        })
}

pub(crate) fn visit_suites_for_pass(
    suite: &[Stmt],
    owner: SuiteOwner,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for (position, stmt) in suite.iter().enumerate() {
        if matches!(stmt, Stmt::Pass(_))
            && suite.len() > 1
            && !(matches!(owner, SuiteOwner::Class) && position == 0)
        {
            issues.push(issue_at(
                "python:S2772",
                "Remove this unnecessary 'pass'.",
                stmt.range(),
                index,
                source,
            ));
        }
        let nested = if matches!(stmt, Stmt::ClassDef(_)) {
            SuiteOwner::Class
        } else {
            SuiteOwner::Other
        };
        for body in child_bodies(stmt) {
            visit_suites_for_pass(body, nested, issues, index, source);
        }
    }
}

// --- python:S2823 — `__all__` must contain only strings ---------------------

pub(crate) fn is_dunder_all_target(expr: &Expr) -> bool {
    matches!(expr, Expr::Name(name) if name.id.as_str() == "__all__")
}

pub(crate) fn flag_trailing_continue(
    body: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if let Some(Stmt::Continue(last)) = body.last() {
        issues.push(issue_at(
            "python:S3626",
            "Remove this redundant jump statement.",
            last.range(),
            index,
            source,
        ));
    }
}

pub(crate) fn len_zero_verdict(left: &Expr, comparator: &Expr, op: ruff_python_ast::CmpOp) -> bool {
    is_len_call(left)
        && is_zero_literal(comparator)
        && matches!(
            op,
            ruff_python_ast::CmpOp::GtE | ruff_python_ast::CmpOp::Lt | ruff_python_ast::CmpOp::LtE
        )
}

pub(crate) fn len_zero_verdict_swapped(
    left: &Expr,
    comparator: &Expr,
    op: ruff_python_ast::CmpOp,
) -> bool {
    is_len_call(comparator)
        && is_zero_literal(left)
        && matches!(
            op,
            ruff_python_ast::CmpOp::LtE | ruff_python_ast::CmpOp::Gt | ruff_python_ast::CmpOp::GtE
        )
}

pub(crate) fn is_len_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call) if called_name(&call.func) == Some("len") && call.arguments.args.len() == 1)
}

pub(crate) fn is_jump_terminator(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_)
    )
}

/// RSPEC exempts trivially true identities over the `0`/`1` literals.
pub(crate) fn excluded_identical_pair(left: &Expr, right: &Expr) -> bool {
    is_small_int_literal(left) && is_small_int_literal(right)
}

pub(crate) fn is_small_int_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::NumberLiteral(number)
            if matches!(&number.value, ruff_python_ast::Number::Int(value) if matches!(value.as_u8(), Some(0 | 1)))
    )
}

pub(crate) fn flag_duplicate_branches(
    branches: &[&[Stmt]],
    rule_key: &str,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for (later_index, later) in branches.iter().enumerate() {
        for earlier in &branches[..later_index] {
            if ranges_textually_equal(suite_span(later), suite_span(earlier), source) {
                issues.push(issue_at(
                    rule_key,
                    "This branch duplicates an earlier one; merge them or change one implementation.",
                    suite_span(later),
                    index,
                    source,
                ));
                break;
            }
        }
    }
}

pub(crate) fn is_assignable_shape(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Name(_) | Expr::Attribute(_) | Expr::Subscript(_)
    )
}

pub(crate) fn flag_comprehension_walrus(
    element: &Expr,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if matches!(element, Expr::Named(_)) {
        issues.push(issue_at(
            "python:S5685",
            "Move this walrus operator to a clearer location.",
            element.range(),
            index,
            source,
        ));
    }
}

pub(crate) fn is_freshly_created(expr: &Expr) -> bool {
    match expr {
        Expr::List(_)
        | Expr::Set(_)
        | Expr::Tuple(_)
        | Expr::Dict(_)
        | Expr::ListComp(_)
        | Expr::SetComp(_)
        | Expr::DictComp(_)
        | Expr::Generator(_) => true,
        Expr::Call(call) => matches!(
            called_name(&call.func),
            Some("list" | "dict" | "set" | "tuple" | "frozenset")
        ),
        _ => false,
    }
}

pub(crate) fn is_type_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if called_name(&call.func) == Some("type")
            && call.arguments.args.len() == 1
            && call.arguments.keywords.is_empty())
}

pub(crate) fn is_boundary_slice(expr: &Expr) -> bool {
    let Expr::Subscript(subscript) = expr else {
        return false;
    };
    let Expr::Slice(slice) = subscript.slice.as_ref() else {
        return false;
    };
    if slice.step.is_some() {
        return false;
    }
    match (&slice.lower, &slice.upper) {
        (None, Some(_)) => true,
        (Some(bound), None) => {
            matches!(bound.as_ref(), Expr::UnaryOp(unary)
                if unary.op == ruff_python_ast::UnaryOp::USub
                    && matches!(unary.operand.as_ref(), Expr::NumberLiteral(_)))
        }
        _ => false,
    }
}

pub(crate) fn visit_suites_for_no_effect(
    suite: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for (position, stmt) in suite.iter().enumerate() {
        if let Stmt::Expr(value) = stmt
            && !(position == 0 && matches!(value.value.as_ref(), Expr::StringLiteral(_)))
            && statement_has_no_effect(&value.value)
        {
            issues.push(issue_at(
                "python:S905",
                "Remove this statement; it has no effect.",
                stmt.range(),
                index,
                source,
            ));
        }
        for body in child_bodies(stmt) {
            visit_suites_for_no_effect(body, issues, index, source);
        }
    }
}

pub(crate) fn statement_has_no_effect(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_)
        | Expr::BooleanLiteral(_)
        | Expr::NumberLiteral(_)
        | Expr::StringLiteral(_)
        | Expr::BytesLiteral(_)
        | Expr::EllipsisLiteral(_)
        | Expr::Name(_) => true,
        Expr::Tuple(tuple) => tuple.elts.iter().all(statement_has_no_effect),
        Expr::List(list) => list.elts.iter().all(statement_has_no_effect),
        Expr::Set(set) => set.elts.iter().all(statement_has_no_effect),
        Expr::Dict(dict) => dict.items.iter().all(|item| {
            item.key.as_ref().is_none_or(statement_has_no_effect)
                && statement_has_no_effect(&item.value)
        }),
        Expr::UnaryOp(unary) => statement_has_no_effect(&unary.operand),
        Expr::BinOp(binary) => {
            statement_has_no_effect(&binary.left) && statement_has_no_effect(&binary.right)
        }
        Expr::BoolOp(boolean) => boolean.values.iter().all(statement_has_no_effect),
        Expr::Compare(compare) => {
            statement_has_no_effect(&compare.left)
                && compare.comparators.iter().all(statement_has_no_effect)
        }
        _ => false,
    }
}

/// Names caught by an except type expression (`Name`, attribute tail, or any
/// element of a tuple).
pub(crate) fn exception_type_names(type_expr: Option<&Expr>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(expr) = type_expr {
        collect_exception_names(expr, &mut names);
    }
    names
}

pub(crate) fn collect_exception_names(expr: &Expr, names: &mut Vec<String>) {
    match expr {
        Expr::Name(name) => names.push(name.id.to_string()),
        Expr::Attribute(attribute) => names.push(attribute.attr.to_string()),
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                collect_exception_names(element, names);
            }
        }
        _ => {}
    }
}

// --- python:S5712 — special methods raising NotImplementedError ---------------

// --- python:S5719 — instance/class methods need a positional parameter --------

/// Iterates `(class, function)` for every method directly defined in a class
/// body anywhere in the tree.
pub(crate) fn for_each_method(
    stmts: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtClassDef, &ruff_python_ast::StmtFunctionDef),
) {
    for_each_stmt(stmts, &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            for member in &class.body {
                if let Stmt::FunctionDef(function) = member {
                    visit(class, function);
                }
            }
        }
    });
}

// --- python:S5722 — special method arity --------------------------------------

// --- python:S5709 — custom exceptions inherit Exception -----------------------

pub(crate) fn looks_like_exception_name(name: &str) -> bool {
    name.ends_with("Error") || name.ends_with("Warning") || name.ends_with("Exception")
}

pub(crate) fn scan_flow_statements(
    suite: &[Stmt],
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        match stmt {
            Stmt::Break(_) | Stmt::Continue(_) => {
                flag_flow_jump(stmt, state, issues, index, source);
            }
            Stmt::Return(_) => {
                if state.finally_depth > 0 {
                    issues.push(issue_at(
                        "python:S1143",
                        "Move this return statement out of 'finally'; it discards the in-flight exception.",
                        stmt.range(),
                        index,
                        source,
                    ));
                }
            }
            Stmt::Raise(raised) => flag_flow_raise(raised, state, issues, index, source),
            _ => scan_flow_nested_bodies(stmt, state, issues, index, source),
        }
    }
}

pub(crate) fn flag_flow_jump(
    stmt: &Stmt,
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if state.finally_depth > 0 {
        issues.push(issue_at(
            "python:S1143",
            "Move this jump statement out of 'finally'; it discards the in-flight exception.",
            stmt.range(),
            index,
            source,
        ));
    } else if state.loop_depth == 0 {
        issues.push(issue_at(
            "python:S1716",
            "Remove this jump statement; no enclosing loop exists.",
            stmt.range(),
            index,
            source,
        ));
    }
}

pub(crate) fn flag_flow_raise(
    raised: &ruff_python_ast::StmtRaise,
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if raised.exc.is_some() || raised.cause.is_some() || state.context == RaiseContext::InExcept {
        return;
    }
    let (key, message) = if state.context == RaiseContext::InFinally {
        (
            "python:S5704",
            "A bare 'raise' inside 'finally' masks the in-flight exception.",
        )
    } else {
        (
            "python:S5747",
            "A bare 'raise' is only allowed in an 'except' clause; raise an explicit exception.",
        )
    };
    issues.push(issue_at(key, message, raised.range(), index, source));
}

pub(crate) fn scan_flow_nested_bodies(
    stmt: &Stmt,
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    match stmt {
        Stmt::For(loop_stmt) => {
            scan_flow_statements(&loop_stmt.body, state.with_loop(), issues, index, source);
            scan_flow_statements(&loop_stmt.orelse, state, issues, index, source);
        }
        Stmt::While(loop_stmt) => {
            scan_flow_statements(&loop_stmt.body, state.with_loop(), issues, index, source);
            scan_flow_statements(&loop_stmt.orelse, state, issues, index, source);
        }
        Stmt::Try(try_stmt) => {
            scan_flow_statements(&try_stmt.body, state, issues, index, source);
            for handler in &try_stmt.handlers {
                let ExceptHandler::ExceptHandler(inner) = handler;
                scan_flow_statements(
                    &inner.body,
                    FlowState {
                        context: RaiseContext::InExcept,
                        ..state
                    },
                    issues,
                    index,
                    source,
                );
            }
            scan_flow_statements(&try_stmt.orelse, state, issues, index, source);
            scan_flow_statements(
                &try_stmt.finalbody,
                state.in_finally(),
                issues,
                index,
                source,
            );
        }
        Stmt::With(with_stmt) => {
            scan_flow_statements(&with_stmt.body, state, issues, index, source);
        }
        Stmt::If(if_stmt) => {
            scan_flow_statements(&if_stmt.body, state, issues, index, source);
            for clause in &if_stmt.elif_else_clauses {
                scan_flow_statements(&clause.body, state, issues, index, source);
            }
        }
        Stmt::Match(match_stmt) => {
            for case in &match_stmt.cases {
                scan_flow_statements(&case.body, state, issues, index, source);
            }
        }
        // Jumps bind within the innermost function scope; reset the state.
        Stmt::FunctionDef(function) => {
            scan_flow_statements(
                &function.body,
                FlowState::fresh_scope(),
                issues,
                index,
                source,
            );
        }
        _ => {}
    }
}

pub(crate) fn stmts_load_any_name(stmts: &[Stmt], names: &[String]) -> bool {
    let mut found = false;
    for_each_stmt_expr(stmts, &mut |expr| {
        found |= loads_any_name(expr, names);
    });
    found
}

pub(crate) fn visit_scopes_for_yields(
    suite: &[Stmt],
    function_depth: u32,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        match stmt {
            Stmt::FunctionDef(function) => {
                visit_scopes_for_yields(&function.body, function_depth + 1, issues, index, source);
            }
            Stmt::ClassDef(class) => {
                visit_scopes_for_yields(&class.body, function_depth, issues, index, source);
            }
            _ => {
                if function_depth == 0 {
                    if matches!(stmt, Stmt::Return(_)) {
                        issues.push(issue_at(
                            "python:S2711",
                            "Remove this 'return'; it appears outside a function.",
                            stmt.range(),
                            index,
                            source,
                        ));
                    }
                    for expr in stmt_exprs(stmt) {
                        for_each_expr(expr, &mut |node| match node {
                            Expr::Yield(_) | Expr::YieldFrom(_) => {
                                issues.push(issue_at(
                                    "python:S2711",
                                    "Move this 'yield' into a function; it appears outside one.",
                                    node.range(),
                                    index,
                                    source,
                                ));
                            }
                            _ => {}
                        });
                    }
                }
                for body in child_bodies(stmt) {
                    visit_scopes_for_yields(body, function_depth, issues, index, source);
                }
            }
        }
    }
}

// --- python:S5899 — unreachable test methods ------------------------------------

// --- python:S5915 — assertion at end of except block ---------------------------

// --- python:S7496 — constructor wrapping an existing literal/comprehension ----

// --- python:S7494 — comprehension over a generator expression -----------------

/// `(name, sole positional argument)` for calls shaped `name(x)` without
/// keywords.
pub(crate) fn single_positional_call<'a>(expr: &'a Expr, name: &str) -> Option<&'a Expr> {
    match expr {
        Expr::Call(call)
            if called_name(&call.func) == Some(name)
                && call.arguments.args.len() == 1
                && call.arguments.keywords.is_empty() =>
        {
            Some(&call.arguments.args[0])
        }
        _ => None,
    }
}

pub(crate) fn flag_copy_only(
    element: &Expr,
    generators: &[ruff_python_ast::Comprehension],
    range: TextRange,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let [generator] = generators else { return };
    if generator.ifs.is_empty() && exprs_textually_equal(element, &generator.target, source) {
        issues.push(issue_at(
            "python:S7500",
            "Copy the iterable directly instead of using a comprehension that only renames.",
            range,
            index,
            source,
        ));
    }
}

// --- python:S7506 — static value in dict comprehension ---------------------------

/// Constant expression trees: literals and pure operators only.
pub(crate) fn is_constant_expression(expr: &Expr) -> bool {
    let mut constant = true;
    for_each_expr(expr, &mut |node| {
        constant &= matches!(
            node,
            Expr::NoneLiteral(_)
                | Expr::BooleanLiteral(_)
                | Expr::NumberLiteral(_)
                | Expr::StringLiteral(_)
                | Expr::BytesLiteral(_)
                | Expr::EllipsisLiteral(_)
                | Expr::Tuple(_)
                | Expr::List(_)
                | Expr::Set(_)
                | Expr::UnaryOp(_)
                | Expr::BinOp(_)
                | Expr::BoolOp(_)
                | Expr::Compare(_)
        );
    });
    constant
}

// --- python:S7508 — redundant identical nested constructors ----------------------

// ---------------------------------------------------------------------------
// Tier-A battery entries #111–#193 (python:S1192 … python:S7489).
//
// One private check per catalog entry, aggregated through
// `check_tier_a_battery_2`. Detection follows the batch spec: single-file
// AST/token/text heuristics with deliberately conservative predicates.
// ---------------------------------------------------------------------------

/// Dotted path of a pure `a.b.c` chain rooted at a name; calls and other
/// expressions break the chain.
pub(crate) fn dotted_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(name) => Some(name.id.as_str().to_string()),
        Expr::Attribute(attr) => Some(format!(
            "{}.{}",
            dotted_name(&attr.value)?,
            attr.attr.as_str()
        )),
        _ => None,
    }
}

/// `(dotted callee path, arguments)` of a call whose callee is a plain name
/// or a dotted attribute chain.
pub(crate) fn call_parts(expr: &Expr) -> Option<(String, &ruff_python_ast::Arguments)> {
    match expr {
        Expr::Call(call) => dotted_name(&call.func).map(|path| (path, &call.arguments)),
        _ => None,
    }
}

pub(crate) fn keyword_value<'a>(
    arguments: &'a ruff_python_ast::Arguments,
    name: &str,
) -> Option<&'a Expr> {
    arguments.keywords.iter().find_map(|keyword| {
        let arg = keyword.arg.as_ref()?;
        (arg.as_str() == name).then_some(&keyword.value)
    })
}

pub(crate) fn has_keyword(arguments: &ruff_python_ast::Arguments, name: &str) -> bool {
    keyword_value(arguments, name).is_some()
}

pub(crate) fn is_true_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::BooleanLiteral(literal) if literal.value)
}

pub(crate) fn is_false_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::BooleanLiteral(literal) if !literal.value)
}

pub(crate) fn int_literal_value(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64(),
            _ => None,
        },
        _ => None,
    }
}

/// Decoded text of a plain (non-f-string, non-bytes) string literal.
pub(crate) fn string_literal_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(literal) => Some(string_value_text(&literal.value)),
        _ => None,
    }
}

/// Root name of a pure attribute chain (`df` in `df.groupby(...)`).
pub(crate) fn receiver_root(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attr) => receiver_root(&attr.value),
        Expr::Call(call) => receiver_root(&call.func),
        _ => None,
    }
}

/// Visits every call reachable from a statement tree, including calls nested
/// in expressions and compound-statement headers.
pub(crate) fn for_each_call(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::ExprCall),
) {
    for_each_stmt(module_body, &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if let Expr::Call(call) = expr {
                    visit(call);
                }
            });
        }
    });
}

/// Whether the module shows evidence of an actual boto3 client/resource
/// binding: a `boto3.client`/`boto3.resource` call, a `boto3.Session`
/// construction, or `.client(`/`.resource(` reached through a `boto3` or
/// session object. The AWS/cdk-family checks only evaluate calls on
/// resolvable boto3 clients, so they stay silent without such a binding
/// (stub objects like `client = object()` never qualify).
pub(crate) fn has_boto3_binding(module_body: &[Stmt]) -> bool {
    let mut found = false;
    for_each_call(module_body, &mut |call| {
        if found {
            return;
        }
        let Expr::Attribute(attribute) = &*call.func else {
            return;
        };
        match attribute.attr.as_str() {
            "client" | "resource" => {
                found = expr_chain_mentions(&attribute.value, &["boto3", "session"]);
            }
            "Session" => found = expr_chain_mentions(&attribute.value, &["boto3"]),
            _ => {}
        }
    });
    found
}

/// Whether any name inside the expression tree equals one of `names`.
fn expr_chain_mentions(expr: &Expr, names: &[&str]) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |child| {
        if let Expr::Name(name) = child {
            found |= names.contains(&name.id.as_str());
        }
    });
    found
}

pub(crate) fn is_standalone_string_stmt(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Expr(expr) if matches!(expr.value.as_ref(), Expr::StringLiteral(_)))
}

/// Naive matcher for the `exclusionRegex` option: a plain substring when the
/// pattern is free of regex metacharacters, otherwise no exclusion.
pub(crate) fn excluded_by_pattern(pattern: &str, value: &str) -> bool {
    !pattern.is_empty()
        && !pattern.chars().any(|c| "\\^$.|?*+()[]{}".contains(c))
        && value.contains(pattern)
}

// --- python:S5828 — invalid open modes ---------------------------------------

// --- python:S4790 — weak hashing algorithms -----------------------------------

// --- python:S5361 — re.sub with a metacharacter-free pattern --------------------

// --- python:S3984 — exception instantiated but never raised ---------------------

// ---------------------------------------------------------------------------
// Entries #112–#154 continued: NumPy/Math/Pandas/TensorFlow/scikit-learn/
// PyTorch heuristics and Django conventions.
// ---------------------------------------------------------------------------

/// Visits every expression reachable from a module body, including compound
/// statement headers.
pub(crate) fn for_each_expr_in_module(module_body: &[Stmt], visit: &mut impl FnMut(&Expr)) {
    for_each_stmt(module_body, &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, visit);
        }
    });
}

pub(crate) fn is_zero_number_literal(expr: &Expr) -> bool {
    match expr {
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64() == Some(0),
            ruff_python_ast::Number::Float(value) => *value == 0.0,
            ruff_python_ast::Number::Complex { .. } => false,
        },
        _ => false,
    }
}

// --- python:S6725 — equality against numpy.nan --------------------------------

// --- python:S6730 — deprecated NumPy scalar aliases ------------------------------

// --- pandas heuristics ------------------------------------------------------------

pub(crate) const PANDAS_INPLACE_METHODS: [&str; 13] = [
    "reset_index",
    "drop",
    "dropna",
    "fillna",
    "ffill",
    "bfill",
    "sort_values",
    "sort_index",
    "rename",
    "replace",
    "set_index",
    "round",
    "clip",
];

/// Names bound directly to a DataFrame-shaped construction in this file.
pub(crate) fn collect_dataframe_variables(module_body: &[Stmt]) -> Vec<String> {
    const CONSTRUCTORS: [&str; 7] = [
        "pd.DataFrame",
        "pandas.DataFrame",
        "pd.read_csv",
        "pandas.read_csv",
        "DataFrame",
        "read_csv",
        "read_table",
    ];
    let mut names = Vec::new();
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::Assign(assign) = stmt
            && let [Expr::Name(target)] = assign.targets.as_slice()
            && let Expr::Call(call) = assign.value.as_ref()
            && dotted_name(&call.func).is_some_and(|path| CONSTRUCTORS.contains(&path.as_str()))
        {
            names.push(target.id.to_string());
        }
    });
    names
}

/// Number of consecutive attribute/method segments in a receiver chain.
pub(crate) fn method_chain_length(expr: &Expr) -> u32 {
    match expr {
        // Every `x.m` access is one hop; the surrounding `(...)` call merges
        // into that hop instead of adding another.
        Expr::Attribute(attribute) => 1 + method_chain_length(&attribute.value),
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Attribute(_) => method_chain_length(&call.func),
            _ => 1 + method_chain_length(&call.func),
        },
        _ => 0,
    }
}

/// Flags maximal DataFrame-rooted method chains beyond the RSPEC length.
pub(crate) fn visit_dataframe_chain(
    expr: &Expr,
    dataframes: &[String],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    const CHAIN_LIMIT: u32 = 4;
    let dataframe_rooted =
        receiver_root(expr).is_some_and(|root| dataframes.iter().any(|name| name == root));
    if dataframe_rooted && method_chain_length(expr) >= CHAIN_LIMIT {
        issues.push(issue_at(
            "python:S6742",
            "Break up this long method chain or use pipe().",
            expr.range(),
            index,
            source,
        ));
        return;
    }
    for child in child_exprs(expr) {
        visit_dataframe_chain(child, dataframes, issues, index, source);
    }
}

// --- python:S6900 — invalid NumPy weekmasks ---------------------------------------

// --- python:S6882 — out-of-range date/time components -----------------------------

// --- python:S6929 / python:S6925 — TensorFlow reduction/gather contracts -------------

// --- python:S6919 / python:S6974 — Keras Model / BaseEstimator subclass contracts ----

pub(crate) fn class_base_paths(class: &ruff_python_ast::StmtClassDef) -> Vec<String> {
    class
        .arguments
        .as_ref()
        .map(|arguments| arguments.args.iter().filter_map(dotted_name).collect())
        .unwrap_or_default()
}

pub(crate) fn base_tail_is(path: &str, tail: &str) -> bool {
    path.rsplit('.').next() == Some(tail)
}

pub(crate) fn is_super_init_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if matches!(call.func.as_ref(), Expr::Attribute(attr)
            if attr.attr.as_str() == "__init__"
                && matches!(attr.value.as_ref(), Expr::Call(outer)
                    if called_name(&outer.func) == Some("super"))))
}

pub(crate) fn is_self_attribute(target: &Expr, tail_predicate: impl Fn(&str) -> bool) -> bool {
    matches!(target, Expr::Attribute(attribute)
        if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
            && tail_predicate(attribute.attr.as_str()))
}

/// Einops pattern grammar subset: one `->`, balanced parentheses per side,
/// identifier/ellipsis/`1` tokens only, identical multisets on both sides.
pub(crate) fn einops_pattern_error(pattern: &str) -> Option<&'static str> {
    let sides: Vec<&str> = pattern.splitn(2, "->").collect();
    if sides.len() != 2 {
        return Some("expected exactly one '->'");
    }
    let mut token_lists: Vec<Vec<&str>> = Vec::new();
    for side in sides {
        let mut depth: i64 = 0;
        let mut tokens: Vec<&str> = Vec::new();
        for token in side.split_whitespace() {
            let valid = token == "..." || token.chars().all(|c| c.is_alphanumeric() || c == '_');
            if !valid {
                return Some("invalid token");
            }
            for ch in token.chars() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                if depth < 0 {
                    return Some("unbalanced parentheses");
                }
            }
            tokens.push(token);
        }
        if depth != 0 {
            return Some("unbalanced parentheses");
        }
        tokens.sort_unstable();
        token_lists.push(tokens);
    }
    if token_lists[0] != token_lists[1] {
        return Some("axis names must match on both sides");
    }
    None
}

// --- python:S6969 / S6973 / S6971 — scikit-learn contracts ---------------------------

pub(crate) fn required_estimator_parameters(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "KMeans" => Some(&["n_clusters"]),
        "PCA" | "TruncatedSVD" | "NMF" => Some(&["n_components"]),
        "SGDClassifier" | "SGDRegressor" => Some(&["max_iter", "tol"]),
        _ => None,
    }
}

/// Names bound to `Pipeline(...)` constructions that enable caching.
pub(crate) fn collect_caching_pipeline_variables(module_body: &[Stmt]) -> Vec<String> {
    let mut names = Vec::new();
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::Assign(assign) = stmt
            && let [Expr::Name(target)] = assign.targets.as_slice()
            && let Expr::Call(call) = assign.value.as_ref()
            && called_name(&call.func) == Some("Pipeline")
            && has_keyword(&call.arguments, "memory")
        {
            names.push(target.id.to_string());
        }
    });
    names
}

// --- Django conventions ---------------------------------------------------------------

pub(crate) const DJANGO_STRING_FIELDS: [&str; 4] =
    ["CharField", "TextField", "SlugField", "EmailField"];

pub(crate) fn class_defines_method(class: &ruff_python_ast::StmtClassDef, name: &str) -> bool {
    class
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::FunctionDef(function) if function.name.as_str() == name))
}

pub(crate) fn is_locals_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call) if called_name(&call.func) == Some("locals"))
}

pub(crate) fn meta_declares_fields(meta: &ruff_python_ast::StmtClassDef) -> bool {
    meta.body.iter().any(|stmt| {
        let target_name = match stmt {
            Stmt::Assign(assign) => assign.targets.first().and_then(|target| match target {
                Expr::Name(name) => Some(name.id.as_str().to_string()),
                _ => None,
            }),
            Stmt::AnnAssign(assign) => match assign.target.as_ref() {
                Expr::Name(name) => Some(name.id.as_str().to_string()),
                _ => None,
            },
            _ => None,
        };
        matches!(target_name.as_deref(), Some("fields" | "exclude"))
    })
}

pub(crate) const ROUTE_DECORATOR_TAILS: [&str; 9] = [
    "route", "get", "post", "put", "patch", "delete", "head", "options", "receiver",
];

/// Callee path of a decorator expression (`app.route` for `@app.route("/")`).
pub(crate) fn decorator_callee_path(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Call(call) => dotted_name(&call.func),
        _ => dotted_name(expr),
    }
}

pub(crate) fn assignment_target_leaf_name(target: &Expr) -> Option<String> {
    match target {
        Expr::Name(name) => Some(name.id.as_str().to_string()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str().to_string()),
        _ => None,
    }
}

pub(crate) fn sleep_call_tail(call: &ruff_python_ast::ExprCall) -> Option<String> {
    dotted_name(&call.func)
        .and_then(|path| path.rsplit('.').next().map(str::to_string))
        .filter(|tail| tail == "sleep")
}

pub(crate) fn flag_sync_calls_inside_async(
    module_body: &[Stmt],
    accepted: &impl Fn(&ruff_python_ast::ExprCall) -> bool,
    rule_key: &str,
    message: &str,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for_each_call_in_fn_context(module_body, &mut |call, ctx| {
        if context_is_async(ctx) && accepted(call) {
            issues.push(issue_at(rule_key, message, call.range(), index, source));
        }
    });
}

pub(crate) fn function_parameters(
    function: &ruff_python_ast::StmtFunctionDef,
) -> Vec<&ruff_python_ast::ParameterWithDefault> {
    let parameters = &function.parameters;
    parameters
        .posonlyargs
        .iter()
        .chain(parameters.args.iter())
        .chain(parameters.kwonlyargs.iter())
        .collect()
}

// --- python:S7487 / S7493 / S7499 / S7501 / S7488 / S7489 — blocking calls -------

pub(crate) const SYNC_OS_CALLS: [&str; 9] = [
    "os.system",
    "os.popen",
    "os.fork",
    "os.forkpty",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.posix_spawn",
];

pub(crate) const SYNC_FILE_CALLS: [&str; 10] = [
    "open",
    "io.open",
    "os.open",
    "os.read",
    "os.write",
    "os.remove",
    "os.rename",
    "os.listdir",
    "os.makedirs",
    "os.mkdir",
];

pub(crate) const ASYNC_FILE_METHODS: [&str; 4] =
    ["read_text", "read_bytes", "write_text", "write_bytes"];

pub(crate) const SYNC_HTTP_CALLS: [&str; 19] = [
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "requests.request",
    "requests.Session",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.head",
    "httpx.options",
    "httpx.request",
    "httpx.Client",
    "urllib.request.urlopen",
];

// --- python:S7503 — async function without async features ---------------------------

// --- python:S7513 / python:S7514 — nursery blocks ------------------------------------

pub(crate) fn nursery_context_expression(expr: &Expr) -> bool {
    match expr {
        Expr::Name(name) => {
            matches!(name.id.as_str(), "nursery" | "task_group")
        }
        _ => call_parts(expr).is_some_and(|(path, _)| {
            matches!(
                path.as_str(),
                "trio.open_nursery"
                    | "anyio.create_task_group"
                    | "asyncio.TaskGroup"
                    | "open_nursery"
                    | "create_task_group"
                    | "TaskGroup"
            )
        }),
    }
}

pub(crate) fn is_nursery_block(with_stmt: &ruff_python_ast::StmtWith) -> bool {
    with_stmt.is_async
        && with_stmt
            .items
            .iter()
            .any(|item| nursery_context_expression(&item.context_expr))
}

pub(crate) fn for_each_nursery_block(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtWith),
) {
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::With(with_stmt) = stmt
            && is_nursery_block(with_stmt)
        {
            visit(with_stmt);
        }
    });
}

// ---------------------------------------------------------------------------
// Typing-syntax rules (#168–#178).
// ---------------------------------------------------------------------------

/// Visits every annotation expression in the tree: parameter annotations,
/// return annotations, and annotated assignments.
pub(crate) fn for_each_annotation(module_body: &[Stmt], visit: &mut impl FnMut(&Expr)) {
    for_each_stmt(module_body, &mut |stmt| match stmt {
        Stmt::FunctionDef(function) => {
            for parameter in function_parameters(function) {
                if let Some(annotation) = &parameter.parameter.annotation {
                    visit(annotation);
                }
            }
            if let Some(returns) = &function.returns {
                visit(returns);
            }
        }
        Stmt::AnnAssign(assign) => visit(&assign.annotation),
        _ => {}
    });
}

/// Whether raw (unmasked) source declares PEP 695 `type X = ...` aliases.
pub(crate) fn pep695_aliases_present(parsed: &Parsed<ModModule>, source: &str) -> bool {
    unmasked_segments(parsed, source)
        .iter()
        .any(|(_, segment)| {
            segment.lines().any(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("type ") && trimmed.contains('=')
            })
        })
}

/// Names bound by `X = TypeVar(...)` assignments anywhere in the tree.
pub(crate) fn collect_typevar_names(module_body: &[Stmt]) -> Vec<String> {
    let mut names = Vec::new();
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::Assign(assign) = stmt
            && let [Expr::Name(target)] = assign.targets.as_slice()
            && let Expr::Call(call) = assign.value.as_ref()
            && called_name(&call.func) == Some("TypeVar")
        {
            names.push(target.id.to_string());
        }
    });
    names
}

// ---------------------------------------------------------------------------
// Unittest/misc remainder (#180–#192) and #185–#189 companions.
// ---------------------------------------------------------------------------

pub(crate) const COMPARISON_ASSERTS: [&str; 8] = [
    "assertEqual",
    "assertNotEqual",
    "assertAlmostEqual",
    "assertNotAlmostEqual",
    "assertGreater",
    "assertGreaterEqual",
    "assertLess",
    "assertLessEqual",
];

pub(crate) fn assertion_literal_kind(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::StringLiteral(_) => Some(0),
        Expr::BytesLiteral(_) => Some(1),
        Expr::BooleanLiteral(_) => Some(2),
        Expr::NumberLiteral(_) => Some(3),
        Expr::NoneLiteral(_) => Some(4),
        _ => None,
    }
}

// --- python:S5549 — identical arguments repeated within one call ------------------

// --- python:S5906 / python:S5914 — imprecise and unconditional asserts ---------------

pub(crate) fn unconditional_assert_verdict(
    call: &ruff_python_ast::ExprCall,
    _source: &str,
) -> Option<&'static str> {
    let args = &call.arguments.args;
    // CE flags only constant boolean literals in assertTrue/assertFalse;
    // `assertEqual(x, x)` forms are beyond the CE engine's scope.
    match called_name(&call.func) {
        Some("assertTrue") if args.len() == 1 => match &args[0] {
            Expr::BooleanLiteral(literal) if literal.value => Some("passes"),
            Expr::BooleanLiteral(_) => Some("fails"),
            _ => None,
        },
        Some("assertFalse") if args.len() == 1 => match &args[0] {
            Expr::BooleanLiteral(literal) if !literal.value => Some("passes"),
            Expr::BooleanLiteral(_) => Some("fails"),
            _ => None,
        },
        _ => None,
    }
}

// --- python:S6709 — unseeded randomness (file-level presence heuristic) ---------------

// --- python:S139 — comments at the end of code lines -----------------------------------

// --- python:S4143 — collection content replaced unconditionally ------------------------

// --- python:S4144 — identical sibling function implementations --------------------------

pub(crate) fn body_is_trivial(body: &[Stmt]) -> bool {
    match body.len() {
        0 => true,
        1 => matches!(&body[0], Stmt::Pass(_) | Stmt::Expr(_)),
        _ => false,
    }
}

pub(crate) fn flag_identical_function_pairs(
    suite: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let definitions: Vec<&ruff_python_ast::StmtFunctionDef> = suite
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::FunctionDef(function) => Some(function),
            _ => None,
        })
        .collect();
    for (position, later) in definitions.iter().enumerate().skip(1) {
        for earlier in &definitions[..position] {
            if body_is_trivial(&earlier.body)
                || body_is_trivial(&later.body)
                || !ranges_textually_equal(
                    suite_span(&earlier.body),
                    suite_span(&later.body),
                    source,
                )
            {
                continue;
            }
            issues.push(issue_at(
                "python:S4144",
                &format!(
                    "Refactor this function; it duplicates the implementation of '{}'.",
                    earlier.name.as_str()
                ),
                later.name.range(),
                index,
                source,
            ));
            break;
        }
    }
}

// --- python:S5717 — modified/assigned parameters ----------------------------------------

// --- python:S5797 — constant conditions ---------------------------------------------------

pub(crate) fn constant_truth(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::BooleanLiteral(literal) => Some(literal.value),
        Expr::NoneLiteral(_) => Some(false),
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64().map(|value| value != 0),
            ruff_python_ast::Number::Float(value) => Some(*value != 0.0),
            ruff_python_ast::Number::Complex { .. } => None,
        },
        Expr::StringLiteral(literal) => Some(!string_value_text(&literal.value).is_empty()),
        Expr::BoolOp(bool_op) => {
            let operands: Option<Vec<bool>> = bool_op.values.iter().map(constant_truth).collect();
            operands.map(|operands| match bool_op.op {
                ruff_python_ast::BoolOp::And => operands.iter().all(|value| *value),
                ruff_python_ast::BoolOp::Or => operands.iter().any(|value| *value),
            })
        }
        _ => None,
    }
}

pub(crate) const BUILTIN_NAMES: &[&str] = &[
    "abs",
    "all",
    "any",
    "ascii",
    "bin",
    "bool",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "compile",
    "complex",
    "delattr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "eval",
    "exec",
    "exit",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "help",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "locals",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "property",
    "quit",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
    "__import__",
    "__name__",
    "__file__",
    "__doc__",
    "__spec__",
    "__package__",
    "__loader__",
    "__builtins__",
    "__debug__",
    "__annotations__",
    "__cached__",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BaseException",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "BytesWarning",
    "ChildProcessError",
    "ConnectionAbortedError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "DeprecationWarning",
    "EOFError",
    "EnvironmentError",
    "Exception",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "FutureWarning",
    "GeneratorExit",
    "IOError",
    "ImportError",
    "ImportWarning",
    "IndentationError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "NotADirectoryError",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PendingDeprecationWarning",
    "PermissionError",
    "ProcessLookupError",
    "RecursionError",
    "ReferenceError",
    "ResourceWarning",
    "RuntimeError",
    "RuntimeWarning",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SyntaxWarning",
    "SystemError",
    "SystemExit",
    "TabError",
    "TimeoutError",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "UnicodeWarning",
    "UserWarning",
    "ValueError",
    "Warning",
    "ZeroDivisionError",
];

pub(crate) fn is_builtin_name(name: &str) -> bool {
    BUILTIN_NAMES.contains(&name)
}

pub(crate) fn is_dunder_name(name: &str) -> bool {
    name.len() >= 4 && name.starts_with("__") && name.ends_with("__")
}

pub(crate) fn is_private_name(name: &str) -> bool {
    name.starts_with('_') && !is_dunder_name(name)
}

/// Catalog semantics for the `python:S1481` `regex` parameter: the default
/// value `(_[a-zA-Z0-9_]*|dummy|unused|ignored)` maps to underscore-prefixed
/// names plus the literal alternatives; custom patterns honor top-level `|`
/// alternations with trailing `*` wildcards and literal names.
pub(crate) fn unused_name_matches_pattern(name: &str, pattern: &str) -> bool {
    let trimmed = pattern.strip_prefix('^').unwrap_or(pattern);
    let trimmed = trimmed.strip_suffix('$').unwrap_or(trimmed);
    trimmed.split('|').any(|alternative| {
        let alternative = alternative.trim();
        if alternative == "_[a-zA-Z0-9_]*" {
            return name.starts_with('_');
        }
        if let Some(prefix) = alternative.strip_suffix('*') {
            return name.starts_with(prefix);
        }
        alternative == name
    })
}

pub(crate) fn named_parameters(
    parameters: &ruff_python_ast::Parameters,
) -> Vec<&ruff_python_ast::ParameterWithDefault> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .collect()
}

pub(crate) fn import_binding_name(alias: &ruff_python_ast::Alias) -> Option<String> {
    let name = alias.name.as_str();
    if name == "*" {
        return None;
    }
    Some(match alias.asname.as_deref() {
        Some(asname) => asname.to_string(),
        None => name.split('.').next().unwrap_or(name).to_string(),
    })
}

pub(crate) fn is_tf_function(function: &ruff_python_ast::StmtFunctionDef) -> bool {
    function.decorator_list.iter().any(|decorator| {
        decorator_callee_path(&decorator.expression).as_deref() == Some("tf.function")
    })
}

pub(crate) fn module_all_exports(parsed: &Parsed<ModModule>) -> Vec<(String, TextRange)> {
    let mut exports: Vec<(String, TextRange)> = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let (targets, value): (&[Expr], Option<&Expr>) = match stmt {
            Stmt::Assign(assign) => (assign.targets.as_slice(), Some(&assign.value)),
            Stmt::AugAssign(augmented) => (
                std::slice::from_ref(augmented.target.as_ref()),
                Some(augmented.value.as_ref()),
            ),
            _ => return,
        };
        if !targets.iter().any(is_dunder_all_target) {
            return;
        }
        let Some(value) = value else { return };
        let elements: &[Expr] = match value {
            Expr::List(list) => &list.elts,
            Expr::Tuple(tuple) => &tuple.elts,
            _ => return,
        };
        for element in elements {
            if let Expr::StringLiteral(literal) = element {
                exports.push((string_value_text(&literal.value), element.range()));
            }
        }
    });
    exports
}

// --- python:S1751 — loops running at most once --------------------------------

// --- python:S2190 — infinite recursion ---------------------------------------

// --- python:S2275 / python:S3457 — printf-style formatting ---------------------

/// Conversion characters of a printf-style format string; `None` marks an
/// invalid or truncated specification.
pub(crate) fn percent_conversions(format_text: &str) -> Option<Vec<u8>> {
    let bytes = format_text.as_bytes();
    let mut conversions = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        if bytes[position] != b'%' {
            position += 1;
            continue;
        }
        position += 1;
        if position >= bytes.len() {
            return None;
        }
        if bytes[position] == b'%' {
            position += 1;
            continue;
        }
        while position < bytes.len() && matches!(bytes[position], b'-' | b'+' | b' ' | b'#' | b'0')
        {
            position += 1;
        }
        while position < bytes.len() && bytes[position].is_ascii_digit() {
            position += 1;
        }
        if position < bytes.len() && bytes[position] == b'.' {
            position += 1;
            while position < bytes.len() && bytes[position].is_ascii_digit() {
                position += 1;
            }
        }
        while position < bytes.len() && matches!(bytes[position], b'h' | b'l' | b'L') {
            position += 1;
        }
        let conversion = *bytes.get(position)?;
        if b"diouxXeEfFgGcrsa".contains(&conversion) {
            conversions.push(conversion);
        } else {
            return None;
        }
        position += 1;
    }
    Some(conversions)
}

/// `(format text, arguments, right operand, span)` of a `%`-formatted string
/// literal; `None` for anything else.
pub(crate) fn percent_format_parts(expr: &Expr) -> Option<(String, Vec<&Expr>, &Expr, TextRange)> {
    let Expr::BinOp(bin_op) = expr else {
        return None;
    };
    if !matches!(bin_op.op, ruff_python_ast::Operator::Mod) {
        return None;
    }
    let Expr::StringLiteral(literal) = bin_op.left.as_ref() else {
        return None;
    };
    let arguments: Vec<&Expr> = match bin_op.right.as_ref() {
        Expr::Tuple(tuple) => tuple.elts.iter().collect(),
        other => vec![other],
    };
    Some((
        string_value_text(&literal.value),
        arguments,
        bin_op.right.as_ref(),
        bin_op.range(),
    ))
}

// --- python:S3516 — invariant function returns --------------------------------

// --- python:S3801 — inconsistent return values --------------------------------

// ---------------------------------------------------------------------------
// effect: effect / retention tracking.
// ---------------------------------------------------------------------------

pub(crate) const SIDE_EFFECT_TAILS: [&str; 10] = [
    "print", "input", "open", "system", "popen", "getcwd", "remove", "rename", "mkdir", "sleep",
];

pub(crate) const LOAD_MODEL_TAILS: [&str; 5] = [
    "load",
    "load_model",
    "load_state_dict",
    "from_pretrained",
    "load_weights",
];

pub(crate) const CANCELLATION_SCOPE_TAILS: [&str; 6] = [
    "move_on_after",
    "fail_after",
    "move_on_if",
    "CancelScope",
    "fail_at",
    "move_on_at",
];

pub(crate) const KNOWN_STEP_HINTS: [&str; 18] = [
    "pipeline",
    "model",
    "clf",
    "reg",
    "scaler",
    "preprocessor",
    "vectorizer",
    "encoder",
    "imputer",
    "transformer",
    "selector",
    "reducer",
    "classifier",
    "regressor",
    "steps",
    "features",
    "numeric",
    "categorical",
];

// --- python:S6911 / S6918 / S6928 — tf.function contracts ----------------------

pub(crate) fn for_each_tf_function_body(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtFunctionDef),
) {
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && is_tf_function(function)
        {
            visit(function);
        }
    });
}

pub(crate) fn for_each_with_in_function_context(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtWith, bool),
) {
    fn walk(
        suite: &[Stmt],
        in_async: bool,
        visit: &mut impl FnMut(&ruff_python_ast::StmtWith, bool),
    ) {
        for stmt in suite {
            match stmt {
                Stmt::FunctionDef(function) => walk(&function.body, function.is_async, visit),
                Stmt::ClassDef(class) => walk(&class.body, false, visit),
                Stmt::With(with_stmt) => {
                    visit(with_stmt, in_async);
                    walk(&with_stmt.body, in_async, visit);
                }
                _ => {
                    for body in child_bodies(stmt) {
                        walk(body, in_async, visit);
                    }
                }
            }
        }
    }
    walk(module_body, false, visit);
}

// --- python:S7490 / python:S7497 — cancellation contracts -----------------------

pub(crate) fn suite_contains_raise(suite: &[Stmt]) -> bool {
    suite.iter().any(|stmt| match stmt {
        Stmt::Raise(_) => true,
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => false,
        _ => child_bodies(stmt)
            .iter()
            .any(|body| suite_contains_raise(body)),
    })
}

/// `(inner text, is_raw)` of one string-literal part.
pub(crate) fn string_part_body(raw: &str) -> (&str, usize, bool) {
    let prefix_len = raw.find(['\'', '"']).unwrap_or(raw.len());
    let prefix = &raw[..prefix_len];
    let is_raw = prefix.contains('r') || prefix.contains('R');
    let quote = raw[prefix_len..].chars().next().unwrap_or('\'');
    let triple = raw[prefix_len..].starts_with(&quote.to_string().repeat(3));
    let body_start = prefix_len + if triple { 3 } else { 1 };
    let body_end = raw.len().saturating_sub(if triple { 3 } else { 1 });
    (
        &raw[body_start.min(body_end)..body_end],
        body_start.min(body_end),
        is_raw,
    )
}

/// Decodes the escape starting at `backslash` (which holds `'\\'`), pushing
/// units and returning the number of bytes consumed.
pub(crate) fn decode_escape(
    body: &str,
    backslash: usize,
    base: TextSize,
    units: &mut Vec<RxUnit>,
) -> usize {
    let bytes = body.as_bytes();
    let mut push = |ch: char, at: usize, octal: bool| {
        units.push(RxUnit {
            ch,
            at: base + TextSize::from(to_u32(at)),
            octal,
        });
    };
    let Some(&first) = bytes.get(backslash + 1) else {
        push('\\', backslash, false);
        return 1;
    };
    match first {
        b'n' => push('\n', backslash, false),
        b't' => push('\t', backslash, false),
        b'r' => push('\r', backslash, false),
        b'f' => push('\u{0c}', backslash, false),
        b'v' => push('\u{0b}', backslash, false),
        b'a' => push('\u{07}', backslash, false),
        b'b' => push('\u{08}', backslash, false),
        b'\\' => push('\\', backslash, false),
        b'\'' => push('\'', backslash, false),
        b'"' => push('"', backslash, false),
        b'0'..=b'7' => return decode_octal_escape(body, backslash, base, units),
        b'x' | b'u' | b'U' => return decode_hex_escape(body, backslash, base, units),
        _ => return decode_unknown_escape(body, backslash, base, units),
    }
    2
}

/// Unknown escapes keep both characters verbatim, exactly like Python; this
/// is what lets `\d` reach the regex parser intact.
pub(crate) fn decode_unknown_escape(
    body: &str,
    backslash: usize,
    base: TextSize,
    units: &mut Vec<RxUnit>,
) -> usize {
    let mut push = |ch: char, at: usize| {
        units.push(RxUnit {
            ch,
            at: base + TextSize::from(to_u32(at)),
            octal: false,
        });
    };
    let rest = &body[backslash + 1..];
    if rest.starts_with('N')
        && rest[1..].starts_with('{')
        && let Some(close) = rest[1..].find('}')
    {
        push('\u{fffd}', backslash);
        return close + 4;
    }
    let ch = rest.chars().next().unwrap_or('\\');
    push('\\', backslash);
    push(ch, backslash + 1);
    1 + ch.len_utf8()
}

/// String-level octal escape (`\0` … `\777`); the produced character is
/// flagged for python:S6537.
pub(crate) fn decode_octal_escape(
    body: &str,
    backslash: usize,
    base: TextSize,
    units: &mut Vec<RxUnit>,
) -> usize {
    let bytes = body.as_bytes();
    let mut value: u32 = 0;
    let mut digits = 0;
    while digits < 3
        && bytes
            .get(backslash + 1 + digits)
            .is_some_and(|b| (b'0'..=b'7').contains(b))
    {
        value = value * 8 + u32::from(bytes[backslash + 1 + digits] - b'0');
        digits += 1;
    }
    units.push(RxUnit {
        ch: char::from_u32(value).unwrap_or('\u{fffd}'),
        at: base + TextSize::from(to_u32(backslash)),
        octal: true,
    });
    1 + digits
}

/// `\xHH`, `\uHHHH`, `\UHHHHHHHH`; invalid forms stay verbatim like Python.
pub(crate) fn decode_hex_escape(
    body: &str,
    backslash: usize,
    base: TextSize,
    units: &mut Vec<RxUnit>,
) -> usize {
    let kind = body.as_bytes()[backslash + 1];
    let width = match kind {
        b'x' => 2,
        b'u' => 4,
        _ => 8,
    };
    let digits = &body[backslash + 2..(backslash + 2 + width).min(body.len())];
    if digits.chars().count() == width
        && digits.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(value) = u32::from_str_radix(digits, 16)
        && let Some(ch) = char::from_u32(value)
    {
        units.push(RxUnit {
            ch,
            at: base + TextSize::from(to_u32(backslash)),
            octal: false,
        });
        return 2 + width;
    }
    units.push(RxUnit {
        ch: '\\',
        at: base + TextSize::from(to_u32(backslash)),
        octal: false,
    });
    units.push(RxUnit {
        ch: char::from_u32(u32::from(kind)).unwrap_or('x'),
        at: base + TextSize::from(to_u32(backslash + 1)),
        octal: false,
    });
    2
}

pub(crate) const REGEX_FUNCTIONS: [&str; 9] = [
    "re.compile",
    "re.match",
    "re.search",
    "re.fullmatch",
    "re.findall",
    "re.finditer",
    "re.sub",
    "re.subn",
    "re.split",
];

/// Whether any sub-expression selects the extended/verbose flag.
pub(crate) fn has_verbose_flag(arguments: &ruff_python_ast::Arguments) -> bool {
    let mut found = false;
    let arg_exprs = arguments
        .args
        .iter()
        .chain(arguments.keywords.iter().map(|k| &k.value));
    for expr in arg_exprs {
        for_each_expr(expr, &mut |e| {
            if matches!(dotted_name(e).as_deref(), Some("re.X" | "re.VERBOSE")) {
                found = true;
            }
        });
    }
    found
}

pub(crate) fn member_in_ranges(ch: char, ranges: &[(char, char)]) -> bool {
    ranges.iter().any(|(low, high)| *low <= ch && ch <= *high)
}

pub(crate) fn ranges_overlap(a: &[(char, char)], b: &[(char, char)]) -> bool {
    a.iter()
        .any(|(l1, h1)| b.iter().any(|(l2, h2)| l1 <= h2 && l2 <= h1))
}

// --- per-rule implementations ------------------------------------------------

pub(crate) fn run_structural_regex_rules(
    parsed: &RxParsed,
    units: &[RxUnit],
    verbose: bool,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let mut push = |key: &str, message: &str, span: TextRange| {
        issues.push(issue_at(key, message, span, index, source));
    };
    check_rx_syntax_shapes(parsed, units, verbose, &mut push);
    check_rx_repetition_hazards(parsed, &mut push);
    check_rx_style_shapes(parsed, source, verbose, options, &mut push);
}

// --- style shapes (S6353, S6396, S6397, S5869, S5868, S5843, S5857) ----------

pub(crate) const CLASS_METACHARACTERS: [char; 15] = [
    '\\', '^', '$', '.', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}', '-',
];

pub(crate) const GRAPHEME_RANGES: [(char, char); 6] = [
    ('\u{0300}', '\u{036F}'),
    ('\u{200D}', '\u{200D}'),
    ('\u{FE00}', '\u{FE0F}'),
    ('\u{20D0}', '\u{20FF}'),
    ('\u{1AB0}', '\u{1AFF}'),
    ('\u{1F1E6}', '\u{1F1FF}'),
];

pub(crate) fn is_grapheme_codepoint(ch: char) -> bool {
    GRAPHEME_RANGES
        .iter()
        .any(|(low, high)| *low <= ch && ch <= *high)
}

pub(crate) fn is_regional_indicator(ch: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&ch)
}

// ---------------------------------------------------------------------------
// Tier C — feasible-heuristic security-sensitive rules.
//
// Every finding below is a true positive by construction: detection rests on
// API name tables, literal argument shapes, or structural patterns confined
// to the analyzed file. Framework-specific subsets are documented per rule.
// ---------------------------------------------------------------------------

/// Last-segment callee match (`a.b(...)` matches `"b"`).
pub(crate) fn is_call_method(call: &ruff_python_ast::ExprCall, method: &str) -> bool {
    called_name(&call.func) == Some(method)
}

/// Exact dotted-path callee match (`a.b.c(...)` matches `"a.b.c"`).
pub(crate) fn is_call_path(call: &ruff_python_ast::ExprCall, path: &str) -> bool {
    dotted_name(&call.func).is_some_and(|p| p == path)
}

/// Dotted-path match against exact entries or prefix families (import-style
/// tolerance: `from Crypto.Cipher import AES; AES.new(k)` resolves through
/// the leading-segment table instead of the full path).
pub(crate) fn call_path_matches(
    call: &ruff_python_ast::ExprCall,
    exact: &[&str],
    prefixes: &[&str],
    heads: &[&str],
) -> bool {
    dotted_name(&call.func).is_some_and(|p| {
        let path = p.as_str();
        exact.contains(&path)
            || prefixes.iter().any(|prefix| path.starts_with(prefix))
            || path
                .split('.')
                .next()
                .is_some_and(|head| heads.contains(&head))
    })
}

/// Loads of `<receiver>.<attr>` attribute expressions.
pub(crate) fn for_each_attr_load(
    stmts: &[Stmt],
    attr: &str,
    mut visit: impl FnMut(&ruff_python_ast::ExprAttribute),
) {
    for_each_stmt_expr(stmts, &mut |expr| {
        if let Expr::Attribute(candidate) = expr
            && candidate.attr.as_str() == attr
        {
            visit(candidate);
        }
    });
}

/// HTTP-client request methods whose TLS verification was disabled with the
/// `verify=False` keyword argument.
pub(crate) fn http_verify_disabled(call: &ruff_python_ast::ExprCall) -> bool {
    const HTTP_METHODS: [&str; 8] = [
        "get", "post", "put", "patch", "delete", "head", "options", "request",
    ];
    HTTP_METHODS.contains(&called_name(&call.func).unwrap_or_default())
        && keyword_value(&call.arguments, "verify").is_some_and(is_false_literal)
}

// --- python:S4423 — weak SSL/TLS protocols ------------------------------------

// --- python:S4426 — cryptographic key generation based on strong parameters --

// --- python:S2092 / S3330 — cookie "secure" and "HttpOnly" flags --------------

/// `set_cookie` calls that do not pass `<flag>=True` (missing or literal
/// `False`); both Flask and Django expose this exact API shape.
pub(crate) fn cookie_flag_missing(call: &ruff_python_ast::ExprCall, flag: &str) -> bool {
    is_call_method(call, "set_cookie")
        && !keyword_value(&call.arguments, flag).is_some_and(is_true_literal)
}

// --- python:S5122 — CORS policy restricted to trusted origins -----------------

// --- python:S5247 / S5439 — HTML autoescaping disabled ------------------------

/// Jinja shapes that switch autoescaping off.
pub(crate) fn autoescape_off(call: &ruff_python_ast::ExprCall) -> bool {
    const AUTOESCAPE_ENGINES: [&str; 2] = ["Environment", "select_autoescape"];
    AUTOESCAPE_ENGINES.contains(&called_name(&call.func).unwrap_or_default())
        && (keyword_value(&call.arguments, "autoescape").is_some_and(is_false_literal)
            || keyword_value(&call.arguments, "enabled").is_some_and(is_false_literal))
}

// --- shared literal helpers ---------------------------------------------------

/// Whether `expr` is a plain string or bytes literal (static by construction).
pub(crate) fn is_static_text_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::StringLiteral(_) | Expr::BytesLiteral(_))
}

/// Approximate byte length of a string/bytes literal's payload, derived from
/// the raw source slice (escape sequences count as written; good enough for
/// "short static secret" heuristics).
pub(crate) fn static_literal_payload_len(expr: &Expr, source: &str) -> Option<usize> {
    let range = expr.range();
    let raw = source.get(range.start().to_usize()..range.end().to_usize())?;
    let quote = raw.find(['"', '\''])?;
    let closing = raw.rfind(['"', '\''])?;
    Some(closing.saturating_sub(quote).saturating_sub(1))
}

/// Whether the lowercase text carries an SQL statement shape.
pub(crate) fn sql_statement_shape(lowercased: &str) -> bool {
    (lowercased.contains("select") && lowercased.contains(" from "))
        || lowercased.contains("insert into")
        || (lowercased.contains("update ") && lowercased.contains(" set "))
        || lowercased.contains("delete from")
        || lowercased.contains("drop table")
}

// --- python:S4433 — LDAP connections should be authenticated -------------------

// --- python:S5542 — weak cipher modes and paddings -----------------------------

// --- python:S5547 — robust cipher algorithms ------------------------------------

// --- python:S5344 — passwords not stored in plaintext or fast-hashed ----------

// --- python:S2245 — PRNGs in security contexts ---------------------------------

// --- python:S5443 — temporary files in publicly writable directories -----------

// --- python:S2755 — XML parsers vulnerable to XXE -------------------------------

// --- python:S6377 — XML signatures validated securely ---------------------------

// --- python:S2257 — custom cryptographic algorithms -----------------------------

// --- AWS call-shape helpers ----------------------------------------------------

/// Source slice of a whole call expression (name-table text searches).
pub(crate) fn call_source_text<'a>(call: &ruff_python_ast::ExprCall, source: &'a str) -> &'a str {
    let range = call.range();
    source
        .get(range.start().to_usize()..range.end().to_usize())
        .unwrap_or_default()
}

pub(crate) fn for_each_dict_literal(
    stmts: &[Stmt],
    visit: &mut dyn FnMut(&ruff_python_ast::ExprDict),
) {
    for_each_stmt_expr(stmts, &mut |expr| {
        if let Expr::Dict(dict) = expr {
            visit(dict);
        }
    });
}

pub(crate) fn dict_string_entry<'a>(
    dict: &'a ruff_python_ast::ExprDict,
    key: &str,
) -> Option<&'a Expr> {
    dict.items.iter().find_map(|item| {
        item.key
            .as_ref()
            .and_then(string_literal_text)
            .filter(|text| text == key)
            .map(|_| &item.value)
    })
}

pub(crate) fn is_wildcard_string(expr: &Expr) -> bool {
    string_literal_text(expr).as_deref() == Some("*")
}

/// Whether the value is `"*"` or a mapping whose `"AWS"` entry is `"*"`.
pub(crate) fn grants_to_all_principals(expr: &Expr) -> bool {
    match expr {
        Expr::Dict(dict) => dict_string_entry(dict, "AWS").is_some_and(is_wildcard_string),
        _ => is_wildcard_string(expr),
    }
}

/// Whether the value is `"*"` or a list containing `"*"`.
pub(crate) fn includes_wildcard(expr: &Expr) -> bool {
    match expr {
        Expr::List(list) => list.elts.iter().any(is_wildcard_string),
        _ => is_wildcard_string(expr),
    }
}

// --- python:S6265 — S3 buckets not granted to all users -------------------------

// --- python:S6281 — S3 public access fully blocked --------------------------------

// --- AWS policy-dict subtree helpers --------------------------------------------

pub(crate) fn call_subtree_dicts(
    call: &ruff_python_ast::ExprCall,
) -> Vec<&ruff_python_ast::ExprDict> {
    let mut found = Vec::new();
    let mut stack: Vec<&Expr> = call.arguments.args.iter().collect();
    stack.extend(call.arguments.keywords.iter().map(|keyword| &keyword.value));
    while let Some(expr) = stack.pop() {
        if let Expr::Dict(dict) = expr {
            found.push(dict);
        }
        stack.extend(child_exprs(expr));
    }
    found
}

/// Whether any call-subtree dict maps `key` to the given integer.
pub(crate) fn call_subtree_has_port(call: &ruff_python_ast::ExprCall, ports: &[i64]) -> bool {
    call_subtree_dicts(call).iter().any(|dict| {
        ["FromPort", "ToPort"].iter().any(|key| {
            dict_string_entry(dict, key)
                .and_then(int_literal_value)
                .is_some_and(|value| ports.contains(&value))
        })
    })
}

/// Whether any call-subtree dict maps `CidrIp` to `"0.0.0.0/0"`.
pub(crate) fn call_subtree_open_world(call: &ruff_python_ast::ExprCall) -> bool {
    call_subtree_dicts(call).iter().any(|dict| {
        dict_string_entry(dict, "CidrIp")
            .and_then(string_literal_text)
            .as_deref()
            == Some("0.0.0.0/0")
    })
}

/// Calls carrying `<name>=True` as a keyword or inside a subtree dict.
pub(crate) fn sets_true_flag(call: &ruff_python_ast::ExprCall, name: &str) -> bool {
    if keyword_value(&call.arguments, name).is_some_and(is_true_literal) {
        return true;
    }
    call_subtree_dicts(call)
        .iter()
        .any(|dict| dict_string_entry(dict, name).is_some_and(is_true_literal))
}

// --- python:S6317 — wildcard-scoped actions in policies ---------------------------

// --- python:S6321 — administration services restricted by IP ----------------------

// --- python:S6329 — public network access disabled ----------------------------------

// --- literal-kind classification for operator rules --------------------------------

/// Coarse builtin kind of an expression when it is a plain literal; `bool`
/// and `None` are distinct because identity against them is idiomatic.
pub(crate) fn literal_kind(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::NumberLiteral(_) => Some("number"),
        Expr::StringLiteral(_) | Expr::FString(_) => Some("string"),
        Expr::BytesLiteral(_) => Some("bytes"),
        Expr::List(_) => Some("list"),
        Expr::Tuple(_) => Some("tuple"),
        Expr::Set(_) => Some("set"),
        Expr::Dict(_) => Some("dict"),
        Expr::BooleanLiteral(_) => Some("boolean"),
        Expr::NoneLiteral(_) => Some("none"),
        _ => None,
    }
}

pub(crate) fn is_identity_op(op: ruff_python_ast::CmpOp) -> bool {
    matches!(
        op,
        ruff_python_ast::CmpOp::Is | ruff_python_ast::CmpOp::IsNot
    )
}

/// `(op, lhs, rhs)` pairs of a comparison expression.
pub(crate) fn comparison_pairs(
    compare: &ruff_python_ast::ExprCompare,
) -> Vec<(ruff_python_ast::CmpOp, &Expr, &Expr)> {
    let mut pairs = Vec::new();
    let mut lhs = compare.left.as_ref();
    for (op, rhs) in compare.ops.iter().zip(compare.comparators.iter()) {
        pairs.push((*op, lhs, rhs));
        lhs = rhs;
    }
    pairs
}

// --- python:S5795 — identity comparisons with cached types -------------------------

// --- python:S6663 — sequence indexes must provide __index__ ------------------------

// --- literal-kind helpers for the operator/exception family ---------------------

/// Kinds that support neither membership, item access, nor iteration.
pub(crate) const NON_SUPPORTING_KINDS: [&str; 2] = ["number", "boolean"];

pub(crate) fn is_non_supporting_kind(kind: &str) -> bool {
    NON_SUPPORTING_KINDS.contains(&kind)
}

/// Whether `raise <expr>` / `from <expr>` / `except <expr>` is a plain literal
/// that cannot behave like an exception (tuples excluded for legacy forms).
pub(crate) fn is_non_exception_literal(expr: &Expr) -> bool {
    literal_kind(expr).is_some_and(|kind| {
        matches!(
            kind,
            "number" | "string" | "bytes" | "boolean" | "list" | "set" | "dict"
        )
    })
}

pub(crate) fn is_arithmetic_op(op: ruff_python_ast::Operator) -> bool {
    matches!(
        op,
        ruff_python_ast::Operator::Add
            | ruff_python_ast::Operator::Sub
            | ruff_python_ast::Operator::Mult
            | ruff_python_ast::Operator::Div
            | ruff_python_ast::Operator::FloorDiv
            | ruff_python_ast::Operator::Mod
            | ruff_python_ast::Operator::Pow
            | ruff_python_ast::Operator::LShift
            | ruff_python_ast::Operator::RShift
            | ruff_python_ast::Operator::BitAnd
            | ruff_python_ast::Operator::BitOr
            | ruff_python_ast::Operator::BitXor
    )
}

/// Conservative invalidity table for arithmetic between two plain literals.
pub(crate) fn binop_literal_invalid(
    op: ruff_python_ast::Operator,
    left: &str,
    right: &str,
) -> bool {
    let sequence_like = |kind: &str| matches!(kind, "string" | "bytes" | "list" | "tuple");
    if left == "none"
        || right == "none"
        || left == "dict"
        || right == "dict"
        || left == "set"
        || right == "set"
    {
        return true;
    }
    if left == right && matches!(left, "string" | "bytes") {
        return !matches!(op, ruff_python_ast::Operator::Add);
    }
    if left == right && matches!(left, "list" | "tuple") {
        return !matches!(op, ruff_python_ast::Operator::Add);
    }
    let seq_num =
        sequence_like(left) && right == "number" || sequence_like(right) && left == "number";
    if seq_num {
        return !matches!(op, ruff_python_ast::Operator::Mult);
    }
    // Remaining cross-kind pairs (e.g. string with list) are always invalid.
    left != right
}

// --- python:S6662 — unhashable set members and dict keys ---------------------------

/// Fine-grained literal classification (numbers split by numeric type) shared
/// by the Tier-C semantic rules.
pub(crate) fn typed_literal_kind(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::NumberLiteral(number) => Some(match &number.value {
            ruff_python_ast::Number::Int(_) => "int",
            ruff_python_ast::Number::Float(_) => "float",
            ruff_python_ast::Number::Complex { .. } => "complex",
        }),
        Expr::StringLiteral(_) => Some("string"),
        Expr::BytesLiteral(_) => Some("bytes"),
        Expr::BooleanLiteral(_) => Some("boolean"),
        Expr::NoneLiteral(_) => Some("none"),
        Expr::List(_) => Some("list"),
        Expr::Tuple(_) => Some("tuple"),
        Expr::Set(_) => Some("set"),
        Expr::Dict(_) => Some("dict"),
        _ => None,
    }
}

/// Names written by a statement: assignment/annotation/augmented targets,
/// deletions, loop and `with` targets, import bindings, definition names,
/// and `global`/`nonlocal` declarations (which license remote writes).
/// Comprehension and match-capture scopes cannot rebind these names.
pub(crate) fn stmt_store_names(stmt: &Stmt) -> Vec<String> {
    let mut names = Vec::new();
    match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                collect_target_names(target, &mut names);
            }
        }
        Stmt::AnnAssign(assign) => collect_target_names(&assign.target, &mut names),
        Stmt::AugAssign(assign) => collect_target_names(&assign.target, &mut names),
        Stmt::Delete(delete) => {
            for target in &delete.targets {
                collect_target_names(target, &mut names);
            }
        }
        Stmt::For(loop_stmt) => collect_target_names(&loop_stmt.target, &mut names),
        Stmt::With(with_stmt) => {
            for item in &with_stmt.items {
                if let Some(vars) = item.optional_vars.as_deref() {
                    collect_target_names(vars, &mut names);
                }
            }
        }
        Stmt::Import(import) => {
            for alias in &import.names {
                names.extend(import_binding_name(alias));
            }
        }
        Stmt::ImportFrom(import_from) => {
            for alias in &import_from.names {
                names.extend(import_binding_name(alias));
            }
        }
        Stmt::FunctionDef(function) => names.push(function.name.as_str().to_string()),
        Stmt::ClassDef(class) => names.push(class.name.as_str().to_string()),
        Stmt::Global(global) => {
            for name in &global.names {
                names.push(name.as_str().to_string());
            }
        }
        Stmt::Nonlocal(nonlocal_stmt) => {
            for name in &nonlocal_stmt.names {
                names.push(name.as_str().to_string());
            }
        }
        _ => {}
    }
    names
}

/// Module names provably holding a non-callable literal: assigned a literal
/// exactly once across the whole file by a top-level `name = <literal>`
/// statement. Any second write (loop targets, walrus, `global` declarations,
/// deletion) disqualifies the name.
pub(crate) fn collect_module_literal_bindings(module: &[Stmt]) -> HashSet<String> {
    let mut writes: HashMap<String, usize> = HashMap::new();
    let mut count_writes = |names: Vec<String>| {
        for name in names {
            *writes.entry(name).or_insert(0) += 1;
        }
    };
    for_each_stmt(module, &mut |stmt| {
        count_writes(stmt_store_names(stmt));
        for_each_stmt_expr(std::slice::from_ref(stmt), &mut |expr| {
            if let Expr::Named(named) = expr {
                let mut targets = Vec::new();
                collect_target_names(&named.target, &mut targets);
                count_writes(targets);
            }
        });
    });
    let mut candidates = HashSet::new();
    for stmt in module {
        if let Stmt::Assign(assign) = stmt
            && let [target] = assign.targets.as_slice()
            && let Expr::Name(name) = target
            && typed_literal_kind(&assign.value).is_some()
        {
            candidates.insert(name.id.as_str().to_string());
        }
    }
    candidates.retain(|name| writes.get(name).copied() == Some(1));
    candidates
}

// --- python:S2201 — return values from pure calls should not be ignored ------

// --- python:S3699 — output of functions returning nothing should not be used -

/// Visits `return` statements of a suite without descending into nested
/// function or class definitions.
pub(crate) fn for_each_return_in_scope(
    suite: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtReturn),
) {
    for stmt in suite {
        match stmt {
            Stmt::Return(returned) => visit(returned),
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
            other => {
                for body in child_bodies(other) {
                    for_each_return_in_scope(body, visit);
                }
            }
        }
    }
}

/// Direct base-class names of a class declaration (plain names only).
pub(crate) fn direct_base_names(class: &ruff_python_ast::StmtClassDef) -> Vec<&str> {
    match class.arguments.as_deref() {
        Some(arguments) => arguments
            .args
            .iter()
            .filter_map(|base| match base {
                Expr::Name(name) => Some(name.id.as_str()),
                _ => None,
            })
            .collect(),
        None => Vec::new(),
    }
}

/// Depth-first statement walk tracking the innermost file-local class name so
/// `self.`/`cls.` callees can be resolved.
pub(crate) fn for_each_stmt_with_class<'a>(
    stmts: &'a [Stmt],
    class: Option<&'a str>,
    visit: &mut impl FnMut(&'a Stmt, Option<&'a str>),
) {
    for stmt in stmts {
        visit(stmt, class);
        match stmt {
            Stmt::ClassDef(nested) => {
                for_each_stmt_with_class(&nested.body, Some(nested.name.as_str()), visit);
            }
            other => {
                for body in child_bodies(other) {
                    for_each_stmt_with_class(body, class, visit);
                }
            }
        }
    }
}

// --- python:S930 — call arguments should match parameters ----------------------

/// Positional parameter entries of a signature, optionally skipping the
/// leading bound parameter (`self`/`cls`).
pub(crate) fn parameter_entries(
    parameters: &ruff_python_ast::Parameters,
    skip_receiver: bool,
) -> Vec<&ruff_python_ast::ParameterWithDefault> {
    let all: Vec<&ruff_python_ast::ParameterWithDefault> = parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .collect();
    if skip_receiver && !all.is_empty() {
        all.into_iter().skip(1).collect()
    } else {
        all
    }
}

/// Flags one literal argument whose kind contradicts the parameter's simple
/// concrete annotation.
pub(crate) fn s5655_check_argument(
    entry: &ruff_python_ast::ParameterWithDefault,
    argument: &Expr,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let Some(annotation) = entry.parameter.annotation.as_deref() else {
        return;
    };
    let Some(hint) = concrete_hint(annotation) else {
        return;
    };
    let Some(kind) = typed_literal_kind(argument) else {
        return;
    };
    if hint_accepts_literal(hint, kind) {
        return;
    }
    let annotation_text = expr_normalized_text(annotation, source);
    issues.push(issue_at(
        "python:S5655",
        &format!("This argument does not match the '{annotation_text}' parameter type."),
        argument.range(),
        index,
        source,
    ));
}

// --- python:S2876 — "__iter__" should return an iterator ----------------------

// --- python:S2638 — method overrides should not change contracts --------------

// --- python:S5713 — subclass and parent should not share an except clause -----

/// Module-level file-local classes by name.
pub(crate) fn module_classes(module: &[Stmt]) -> HashMap<&str, &ruff_python_ast::StmtClassDef> {
    module
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::ClassDef(class) => Some((class.name.as_str(), class)),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tier A — naming conventions (python:S100, python:S101, python:S116,
// python:S117, python:S1542).
// ---------------------------------------------------------------------------

/// Visits every function definition together with its lexical class-body
/// context: definitions written directly in a class body are methods,
/// everything else (module-level functions and functions nested inside other
/// functions) is not. This context partitions python:S100 from python:S1542.
pub(crate) fn for_each_function_def<'a>(
    stmts: &'a [Stmt],
    in_class_body: bool,
    visit: &mut impl FnMut(&'a ruff_python_ast::StmtFunctionDef, bool),
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                visit(function, in_class_body);
                for_each_function_def(&function.body, false, visit);
            }
            Stmt::ClassDef(class) => for_each_function_def(&class.body, true, visit),
            _ => {
                for body in child_bodies(stmt) {
                    for_each_function_def(body, in_class_body, visit);
                }
            }
        }
    }
}

/// `^[a-z_][a-z0-9_]*$` — shared shape of function, method, parameter and
/// local-variable names (python:S100/S1542/S117).
pub(crate) fn matches_snake_case(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
}

/// `^_?([A-Z_][a-zA-Z0-9]*|[a-z_][a-z0-9_]*)$` — class names (python:S101).
pub(crate) fn matches_class_name(name: &str) -> bool {
    let rest = name.strip_prefix('_').unwrap_or(name);
    let mut chars = rest.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first.is_ascii_uppercase() || first == '_' {
        chars.all(|c| c.is_ascii_alphanumeric())
    } else {
        first.is_ascii_lowercase()
            && chars.all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
    }
}

/// `^[_a-z][_a-z0-9]*$` — class-body field names; unlike function and local
/// names no digit may directly follow the leading character (python:S116).
pub(crate) fn matches_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_lowercase() => {}
        _ => return false,
    }
    match chars.next() {
        None => true,
        Some(second) if second == '_' || second.is_ascii_lowercase() => {
            chars.all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit())
        }
        _ => false,
    }
}

/// Name leaves of an assignment-target tree (`a`, `a, b = ...`, `[a] = ...`).
pub(crate) fn binding_target_names(target: &Expr) -> Vec<&Expr> {
    match target {
        Expr::Name(_) => vec![target],
        Expr::Tuple(tuple) => tuple.elts.iter().flat_map(binding_target_names).collect(),
        Expr::List(list) => list.elts.iter().flat_map(binding_target_names).collect(),
        Expr::Starred(starred) => binding_target_names(&starred.value),
        _ => Vec::new(),
    }
}

/// All named parameters of a definition, including `*args` and `**kwargs`.
pub(crate) fn function_all_parameters(
    function: &ruff_python_ast::StmtFunctionDef,
) -> Vec<&ruff_python_ast::Identifier> {
    let parameters = &function.parameters;
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .map(|parameter| &parameter.parameter.name)
        .chain(
            parameters
                .vararg
                .as_deref()
                .map(|parameter| &parameter.name),
        )
        .chain(parameters.kwarg.as_deref().map(|parameter| &parameter.name))
        .collect()
}

/// Bound name-bearing target expressions of a binding statement.
pub(crate) fn binding_stmt_targets(stmt: &Stmt) -> Vec<&Expr> {
    match stmt {
        Stmt::Assign(assign) => assign
            .targets
            .iter()
            .flat_map(binding_target_names)
            .collect(),
        Stmt::AnnAssign(assignment) => binding_target_names(&assignment.target),
        Stmt::AugAssign(assignment) => binding_target_names(&assignment.target),
        Stmt::For(loop_stmt) => binding_target_names(&loop_stmt.target),
        Stmt::With(with_stmt) => with_stmt
            .items
            .iter()
            .filter_map(|item| item.optional_vars.as_deref())
            .flat_map(binding_target_names)
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn push_local_name_issue(
    issues: &mut Vec<Issue>,
    seen: &mut HashSet<String>,
    name: &str,
    range: TextRange,
    index: &LineIndex,
    source: &str,
) {
    if !seen.insert(name.to_string()) || matches_snake_case(name) {
        return;
    }
    issues.push(issue_at(
        "python:S117",
        "Rename this local variable to match the regular expression '^[_a-z][a-z0-9_]*$'.",
        range,
        index,
        source,
    ));
}

/// Counts `return` statements in this function's own body; nested function
/// definitions are separate units with their own budgets.
pub(crate) fn count_own_returns(stmts: &[Stmt]) -> usize {
    stmts
        .iter()
        .map(|stmt| match stmt {
            Stmt::Return(_) => 1,
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => 0,
            _ => child_bodies(stmt)
                .iter()
                .map(|body| count_own_returns(body))
                .sum(),
        })
        .sum()
}

/// Keyword introducing a python:S134 nesting construct.
pub(crate) fn nesting_keyword(stmt: &Stmt) -> Option<&'static str> {
    match stmt {
        Stmt::If(_) => Some("if"),
        Stmt::For(loop_stmt) => Some(if loop_stmt.is_async {
            "async for"
        } else {
            "for"
        }),
        Stmt::While(_) => Some("while"),
        Stmt::Try(_) => Some("try"),
        Stmt::With(with_stmt) => Some(if with_stmt.is_async {
            "async with"
        } else {
            "with"
        }),
        _ => None,
    }
}

pub(crate) fn flag_excess_nesting(
    stmt: &Stmt,
    level: u32,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let Some(keyword) = nesting_keyword(stmt) else {
        return;
    };
    if level <= options.maximum_nesting_depth {
        return;
    }
    let width = TextSize::try_from(keyword.len()).unwrap_or_default();
    issues.push(issue_at(
        "python:S134",
        &format!(
            "Refactor this code to not nest more than {} levels.",
            options.maximum_nesting_depth
        ),
        TextRange::at(stmt.start(), width),
        index,
        source,
    ));
}

/// Walks nesting constructs (If/For/While/Try/With), tracking depth. Elif
/// and else clauses share their `if`'s level; handler bodies share their
/// `try`'s level; nested definitions are units of their own and reset it.
pub(crate) fn walk_nesting_depth(
    stmts: &[Stmt],
    depth: u32,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                walk_nesting_depth(&function.body, 0, options, issues, index, source);
            }
            Stmt::ClassDef(class) => {
                walk_nesting_depth(&class.body, 0, options, issues, index, source);
            }
            Stmt::If(if_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&if_stmt.body, depth + 1, options, issues, index, source);
                for clause in &if_stmt.elif_else_clauses {
                    walk_nesting_depth(&clause.body, depth + 1, options, issues, index, source);
                }
            }
            Stmt::For(loop_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&loop_stmt.body, depth + 1, options, issues, index, source);
                walk_nesting_depth(&loop_stmt.orelse, depth + 1, options, issues, index, source);
            }
            Stmt::While(while_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&while_stmt.body, depth + 1, options, issues, index, source);
                walk_nesting_depth(
                    &while_stmt.orelse,
                    depth + 1,
                    options,
                    issues,
                    index,
                    source,
                );
            }
            Stmt::Try(try_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&try_stmt.body, depth + 1, options, issues, index, source);
                for handler in &try_stmt.handlers {
                    let ExceptHandler::ExceptHandler(inner) = handler;
                    walk_nesting_depth(&inner.body, depth + 1, options, issues, index, source);
                }
                walk_nesting_depth(&try_stmt.orelse, depth + 1, options, issues, index, source);
                walk_nesting_depth(
                    &try_stmt.finalbody,
                    depth + 1,
                    options,
                    issues,
                    index,
                    source,
                );
            }
            Stmt::With(with_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&with_stmt.body, depth + 1, options, issues, index, source);
            }
            _ => {}
        }
    }
}
