// --- Shared helpers for the Tier-A rule battery.

use crate::support::to_u32;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

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
    let has_double_colon = run.contains("::");
    // Full form: 8 groups. Compressed form: `::` with 1+ visible groups.
    // Without `::`, fewer than 8 groups is a time stamp or MAC-style run.
    let valid = (groups.len() == 8 || (has_double_colon && !groups.is_empty()))
        && groups
            .iter()
            .all(|group| group.len() <= 4 && group.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if valid { Some(run.to_string()) } else { None }
}
