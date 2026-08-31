// --- python:S6418 / python:S6437 — hard-coded secrets.

use crate::engine::scope::SuiteOwner;
use crate::support::{
    child_bodies, child_exprs, for_each_expr, is_keyword, string_value_text, to_range,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_python_ast::token::TokenKind;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

pub(crate) const SECRET_ENTROPY_THRESHOLD: f64 = 3.0;

pub(crate) const SECRET_HIGH_ENTROPY_THRESHOLD: f64 = 4.5;

pub(crate) const CREDENTIAL_PREFIXES: [&str; 11] = [
    "ghp_", "gho_", "AKIA", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "sk_live_", "sk-", "AIza", "glpat-",
];

/// Whether a literal starts with a recognizable credential-token prefix
/// (GitHub, Slack, AWS, Stripe, Google API keys).
pub(crate) fn has_credential_prefix(text: &str) -> bool {
    CREDENTIAL_PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

const SECRET_NAME_WORDS: [&str; 5] = ["apikey", "auth", "credential", "secret", "token"];

fn matches_secret_word(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    let singular = lowered.strip_suffix('s').unwrap_or(&lowered);
    SECRET_NAME_WORDS.contains(&lowered.as_str()) || SECRET_NAME_WORDS.contains(&singular)
}

/// Word-boundary secret-name matching: identifiers tokenize on `_`/`-`/`.`,
/// camelCase humps, and letter/digit transitions; a name qualifies when a
/// token (optionally pluralized) equals a secret word or two adjacent tokens
/// join into one (`api` + `key`). Substrings inside one token never match,
/// so `author` and `tokenizer_vocab` stay unflagged while `auth_token`,
/// `secretKey`, and `myApiKey` keep matching.
pub(crate) fn is_secret_name(name: &str) -> bool {
    let mut tokens: Vec<&str> = Vec::new();
    let mut start: Option<usize> = None;
    let mut previous: Option<char> = None;
    for (index, ch) in name.char_indices() {
        let alphanumeric = ch.is_ascii_alphanumeric();
        let boundary = match previous {
            None => true,
            Some(prev) => {
                !alphanumeric
                    || !prev.is_ascii_alphanumeric()
                    || (ch.is_ascii_uppercase() && prev.is_ascii_lowercase())
                    || (ch.is_ascii_digit() != prev.is_ascii_digit())
            }
        };
        if boundary && let Some(begin) = start.take() {
            tokens.push(&name[begin..index]);
        }
        if alphanumeric && start.is_none() {
            start = Some(index);
        }
        previous = Some(ch);
    }
    if let Some(begin) = start {
        tokens.push(&name[begin..]);
    }
    tokens.iter().any(|token| matches_secret_word(token))
        || tokens
            .windows(2)
            .any(|pair| matches_secret_word(&format!("{}{}", pair[0], pair[1])))
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

fn is_valid_escape_byte(byte: u8) -> bool {
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
        fix: None,
        flows: Vec::new(),
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
    let mut pending: Vec<&Stmt> = suite.iter().rev().collect();
    while let Some(stmt) = pending.pop() {
        match stmt {
            Stmt::Break(_) => return true,
            Stmt::For(inner) => pending.extend(inner.orelse.iter().rev()),
            Stmt::While(inner) => pending.extend(inner.orelse.iter().rev()),
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
            _ => {
                for body in child_bodies(stmt).into_iter().rev() {
                    pending.extend(body.iter().rev());
                }
            }
        }
    }
    false
}

pub(crate) fn visit_ifexp_branches(
    expr: &Expr,
    in_branch: bool,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let mut pending = vec![(expr, in_branch)];
    while let Some((expr, in_branch)) = pending.pop() {
        match expr {
            Expr::If(nested) => {
                if in_branch {
                    issues.push(issue_at(
                        "python:S3358",
                        "Extract this nested conditional expression into an independent statement.",
                        nested.range(),
                        index,
                        source,
                    ));
                }
                pending.push((&nested.orelse, true));
                pending.push((&nested.body, true));
                pending.push((&nested.test, false));
            }
            _ => {
                pending.extend(
                    child_exprs(expr)
                        .into_iter()
                        .rev()
                        .map(|child| (child, in_branch)),
                );
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
    let mut pending: Vec<&Stmt> = stmts.iter().rev().collect();
    while let Some(stmt) = pending.pop() {
        visit(stmt);
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        for body in child_bodies(stmt).into_iter().rev() {
            pending.extend(body.iter().rev());
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
                "Remove this unneeded \"pass\".",
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
