use super::{Alternative, alt, issue_range, text_edit};
use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::{
    child_exprs, comparison_pairs, for_each_stmt, function_parameters, is_identity_op, stmt_exprs,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{CmpOp, Expr, ModModule, Number, Operator};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

const FLOAT_TOLERANCE: &str = "1e-09";
const MAX_VISIBLE_SPLIT_COLUMN: usize = 65;

/// Returns all pinned `SonarPython` alternatives owned by this operator family.
///
/// The rule detectors remain responsible for deciding whether an issue exists;
/// these candidates additionally require the syntax and binding evidence needed
/// to preserve the upstream fix's operand and symbol identity semantics.
pub(super) fn alternatives(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    match issue.rule_key.as_str() {
        "python:S1244" => s1244(parsed, index, source, file_ctx, issue),
        "python:S5795" => identity_operator_fix(parsed, index, source, file_ctx, issue, false),
        "python:S5796" => identity_operator_fix(parsed, index, source, file_ctx, issue, true),
        "python:S5799" => s5799(parsed, index, source, file_ctx, issue),
        _ => Vec::new(),
    }
}

fn s1244(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(compare) = file_ctx.exprs.iter().find_map(|expr| match expr {
        Expr::Compare(compare) if compare.range() == issue_span => Some(compare),
        _ => None,
    }) else {
        return Vec::new();
    };
    if compare.ops.len() != 1 || compare.comparators.len() != 1 {
        return Vec::new();
    }
    let operator = compare.ops[0];
    if !matches!(operator, CmpOp::Eq | CmpOp::NotEq) {
        return Vec::new();
    }
    let left = &compare.left;
    let right = &compare.comparators[0];
    if !float_operand_evidence(left) && !float_operand_evidence(right) {
        return Vec::new();
    }
    let Some((module, is_math, needs_import)) = is_close_module(file_ctx, issue_span.start())
    else {
        return Vec::new();
    };
    let not_prefix = if operator == CmpOp::NotEq { "not " } else { "" };
    let left_text = &source[left.range()];
    let right_text = &source[right.range()];
    let (rel_name, abs_name) = if is_math {
        ("rel_tol", "abs_tol")
    } else {
        ("rtol", "atol")
    };
    let replacement = format!(
        "{not_prefix}{module}.isclose({left_text}, {right_text}, {rel_name}={FLOAT_TOLERANCE}, {abs_name}={FLOAT_TOLERANCE})"
    );
    let mut edits = if needs_import && issue_span.start() == TextSize::default() {
        vec![text_edit(
            index,
            source,
            issue_span,
            format!("import math\n{replacement}"),
        )]
    } else {
        vec![text_edit(index, source, issue_span, replacement)]
    };
    if needs_import && issue_span.start() != TextSize::default() {
        let import_offset = file_ctx
            .imports
            .iter()
            .filter_map(|entry| match entry {
                AnyImport::From(import)
                    if import
                        .module
                        .as_ref()
                        .is_some_and(|m| m.as_str() == "__future__") =>
                {
                    Some(import.range().end())
                }
                _ => None,
            })
            .max()
            .unwrap_or_default();
        if import_offset >= issue_span.start() {
            return Vec::new();
        }
        edits.push(text_edit(
            index,
            source,
            TextRange::new(import_offset, import_offset),
            "import math\n",
        ));
    }
    let display_module = format!("{not_prefix}{module}");
    vec![alt(
        "s1244-use-isclose",
        format!("Replace with \"{display_module}.isclose()\"."),
        edits,
    )]
}
/// Returns the first supported import available before the comparison.
fn is_close_module(file_ctx: &FileContext<'_>, before: TextSize) -> Option<(String, bool, bool)> {
    let mut selected: Option<(String, String, bool)> = None;
    for entry in &file_ctx.imports {
        let AnyImport::Plain(import) = entry else {
            continue;
        };
        if import.range().end() > before {
            continue;
        }
        for alias in &import.names {
            let Some(module) = alias
                .name
                .as_str()
                .split('.')
                .find(|segment| matches!(*segment, "numpy" | "torch" | "math"))
            else {
                continue;
            };
            let display = alias
                .asname
                .as_deref()
                .map_or(module.to_string(), ToString::to_string);
            if file_ctx.stmts.iter().any(|stmt| {
                stmt.range().contains(before)
                    && stmt.range() != import.range()
                    && crate::support::stmt_store_names(stmt)
                        .iter()
                        .any(|name| name.as_str() == display)
            }) {
                continue;
            }
            if selected
                .as_ref()
                .is_some_and(|(_, selected_module, _)| selected_module != "math")
            {
                continue;
            }
            selected = Some((display, module.to_string(), module == "math"));
        }
    }
    if let Some((display, _module, is_math)) = selected {
        Some((display, is_math, false))
    } else if file_ctx.stmts.iter().any(|stmt| {
        stmt.range().contains(before)
            && crate::support::stmt_store_names(stmt)
                .iter()
                .any(|name| name == "math")
    }) {
        None
    } else {
        Some(("math".to_string(), true, true))
    }
}

fn float_operand_evidence(expr: &Expr) -> bool {
    match expr {
        Expr::NumberLiteral(number) => matches!(number.value, Number::Float(_)),
        Expr::BinOp(binary)
            if matches!(
                binary.op,
                Operator::Add | Operator::Sub | Operator::Mult | Operator::Div
            ) =>
        {
            float_operand_evidence(&binary.left) || float_operand_evidence(&binary.right)
        }
        _ => false,
    }
}
fn identity_operator_fix(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
    fresh_rule: bool,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let alternative = file_ctx.exprs.iter().find_map(|expr| {
        let Expr::Compare(compare) = expr else {
            return None;
        };
        comparison_pairs(compare)
            .into_iter()
            .find_map(|(op, left, right)| {
                identity_alternative(
                    parsed,
                    index,
                    source,
                    file_ctx,
                    issue_span,
                    &IdentityCandidate {
                        fresh_rule,
                        op,
                        left,
                        right,
                    },
                )
            })
    });
    alternative.into_iter().collect()
}

struct IdentityCandidate<'a> {
    fresh_rule: bool,
    op: CmpOp,
    left: &'a Expr,
    right: &'a Expr,
}

fn identity_alternative(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue_span: TextRange,
    candidate: &IdentityCandidate<'_>,
) -> Option<Alternative> {
    let fresh_rule = candidate.fresh_rule;
    let op = candidate.op;
    let left = candidate.left;
    let right = candidate.right;
    if !is_identity_op(op) || is_none_expr(left) || is_none_expr(right) {
        return None;
    }
    let eligible = if fresh_rule {
        fresh_identity_expr(left, file_ctx) || fresh_identity_expr(right, file_ctx)
    } else {
        cached_identity_expr(left, file_ctx) || cached_identity_expr(right, file_ctx)
    };
    if !eligible {
        return None;
    }
    let span = token_identity_span(parsed, left.range(), right.range(), op)?;
    if span != issue_span {
        return None;
    }
    let (replacement, message, id) = match op {
        CmpOp::Is => ("==", "Replace with \"==\"", "identity-is-to-equals"),
        CmpOp::IsNot => ("!=", "Replace with \"!=\"", "identity-is-not-to-not-equals"),
        _ => return None,
    };
    Some(alt(
        format!("s{}-{id}", if fresh_rule { "5796" } else { "5795" }),
        message,
        vec![text_edit(index, source, span, replacement)],
    ))
}

fn is_none_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::NoneLiteral(_))
}
fn fresh_identity_expr(expr: &Expr, ctx: &FileContext<'_>) -> bool {
    match expr {
        Expr::Dict(_)
        | Expr::DictComp(_)
        | Expr::List(_)
        | Expr::ListComp(_)
        | Expr::Set(_)
        | Expr::SetComp(_) => true,
        Expr::Call(call) => matches!(call.func.as_ref(), Expr::Name(name)
            if matches!(name.id.as_str(), "dict" | "list" | "set" | "complex")
                && constructor_unshadowed(ctx, call.range(), name.id.as_str())),
        _ => false,
    }
}
fn cached_identity_expr(expr: &Expr, ctx: &FileContext<'_>) -> bool {
    match expr {
        Expr::NumberLiteral(n) => matches!(n.value, Number::Int(_) | Number::Float(_)),
        Expr::Call(call) => matches!(call.func.as_ref(), Expr::Name(name)
            if matches!(name.id.as_str(), "frozenset" | "bytes" | "int" | "float" | "str" | "tuple" | "hash")
                && constructor_unshadowed(ctx, call.range(), name.id.as_str())),
        _ => false,
    }
}
fn constructor_unshadowed(ctx: &FileContext<'_>, call_range: TextRange, name: &str) -> bool {
    let scope = ctx
        .functions
        .iter()
        .filter(|f| f.range().contains(call_range.start()))
        .min_by_key(|f| f.range().len());
    if scope.is_some_and(|f| {
        function_parameters(f)
            .iter()
            .any(|p| p.parameter.name.as_str() == name)
    }) {
        return false;
    }
    !ctx.stmts
        .iter()
        .filter(|stmt| match scope {
            Some(f) => {
                f.range().contains(stmt.range().start()) && f.range().contains(stmt.range().end())
            }
            None => !ctx
                .functions
                .iter()
                .any(|f| f.range().contains(stmt.range().start())),
        })
        .any(|stmt| {
            crate::support::stmt_store_names(stmt)
                .iter()
                .any(|stored| stored == name)
        })
}
fn token_identity_span(
    parsed: &Parsed<ModModule>,
    left: TextRange,
    right: TextRange,
    op: CmpOp,
) -> Option<TextRange> {
    let from = left.end();
    let to = right.start();
    let mut tokens = parsed
        .tokens()
        .iter()
        .filter(|t| t.range().start() >= from && t.range().end() <= to);
    match op {
        CmpOp::Is => tokens
            .find(|t| t.kind() == TokenKind::Is)
            .map(Ranged::range),
        CmpOp::IsNot => {
            let mut is = None;
            for t in tokens {
                if t.kind() == TokenKind::Is {
                    is = Some(t.range());
                } else if t.kind() == TokenKind::Not {
                    return Some(TextRange::new(is?.start(), t.range().end()));
                }
            }
            None
        }
        _ => None,
    }
}

fn s5799(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    _file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    for (literal_range, parts) in implicit_literal_parts(parsed) {
        let mut eligible = Vec::new();
        for pair in parts.windows(2) {
            let previous = pair[0];
            let current = pair[1];
            if !same_prefix_and_quotes(&source[previous], &source[current]) {
                continue;
            }
            let same_line =
                line_number(source, previous.start()) == line_number(source, current.start());
            let (collection, blocked) = string_context(parsed, literal_range);
            if blocked
                || (!same_line
                    && (!collection
                        || visible_split_exception(
                            source,
                            &source[previous],
                            &source[current],
                            previous,
                        )))
            {
                continue;
            }
            eligible.push((previous, current, collection));
        }
        let Some((previous, current, collection)) = eligible
            .into_iter()
            .find(|(previous, _, _)| *previous == issue_span)
        else {
            continue;
        };
        let mut alternatives = Vec::new();
        if collection {
            alternatives.push(alt(
                "s5799-add-comma",
                "Add the comma between string or byte tokens.",
                vec![text_edit(
                    index,
                    source,
                    TextRange::new(previous.end(), previous.end()),
                    ",",
                )],
            ));
        }
        alternatives.push(alt(
            "s5799-explicit-addition",
            "Make the addition sign between string or byte tokens explicit.",
            vec![text_edit(
                index,
                source,
                TextRange::new(previous.start(), current.end()),
                format!("{} + {}", &source[previous], &source[current]),
            )],
        ));
        return alternatives;
    }
    Vec::new()
}

fn implicit_literal_parts(parsed: &Parsed<ModModule>) -> Vec<(TextRange, Vec<TextRange>)> {
    let mut literals = Vec::new();
    crate::support::for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let item = match expr {
            Expr::StringLiteral(literal) => (
                literal.range(),
                literal
                    .value
                    .iter()
                    .map(Ranged::range)
                    .collect::<Vec<TextRange>>(),
            ),
            Expr::BytesLiteral(literal) => (
                literal.range(),
                literal
                    .value
                    .iter()
                    .map(Ranged::range)
                    .collect::<Vec<TextRange>>(),
            ),
            _ => return,
        };
        if item.1.len() > 1 {
            literals.push(item);
        }
    });
    literals
}

fn same_prefix_and_quotes(previous: &str, current: &str) -> bool {
    let Some((previous_prefix, previous_quote, previous_triple)) = literal_shape(previous) else {
        return false;
    };
    let Some((current_prefix, current_quote, current_triple)) = literal_shape(current) else {
        return false;
    };
    previous_prefix.eq_ignore_ascii_case(current_prefix)
        && previous_quote == current_quote
        && previous_triple == current_triple
}

fn literal_shape(raw: &str) -> Option<(&str, u8, bool)> {
    let quote_start = raw
        .as_bytes()
        .iter()
        .position(|byte| *byte == b'\'' || *byte == b'"')?;
    let prefix = &raw[..quote_start];
    let quote = raw.as_bytes()[quote_start];
    let triple = raw
        .as_bytes()
        .get(quote_start..quote_start + 3)
        .is_some_and(|slice| slice == [quote, quote, quote]);
    Some((prefix, quote, triple))
}

fn visible_split_exception(
    source: &str,
    previous_raw: &str,
    current_raw: &str,
    previous_range: TextRange,
) -> bool {
    let column = source[..previous_range.start().to_usize()]
        .rsplit_once('\n')
        .map_or(previous_range.start().to_usize(), |(_, line)| line.len());
    if column + previous_raw.len() > MAX_VISIBLE_SPLIT_COLUMN {
        return true;
    }
    let Some(previous_value) = trimmed_literal_value(previous_raw) else {
        return true;
    };
    let Some(current_value) = trimmed_literal_value(current_raw) else {
        return true;
    };
    previous_value.ends_with("\\n")
        || previous_value
            .chars()
            .last()
            .is_some_and(|c| c.is_whitespace() || c.is_ascii_punctuation())
        || current_value.starts_with("\\n")
        || current_value
            .chars()
            .next()
            .is_some_and(|c| c.is_whitespace() || c.is_ascii_punctuation())
}

fn trimmed_literal_value(raw: &str) -> Option<&str> {
    let (_, _, triple) = literal_shape(raw)?;
    let quote_start = raw
        .as_bytes()
        .iter()
        .position(|byte| *byte == b'\'' || *byte == b'"')?;
    let quote_len = if triple { 3 } else { 1 };
    (raw.len() >= quote_start + quote_len * 2)
        .then(|| &raw[quote_start + quote_len..raw.len() - quote_len])
}

fn line_number(source: &str, offset: TextSize) -> usize {
    source[..offset.to_usize()]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
}

fn string_context(parsed: &Parsed<ModModule>, target: TextRange) -> (bool, bool) {
    let mut result = None;
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |statement| {
        if result.is_some() {
            return;
        }
        for expression in stmt_exprs(statement) {
            if let Some(context) = find_string_context(expression, target, false, false) {
                result = Some(context);
                break;
            }
        }
    });
    result.unwrap_or((false, false))
}

fn find_string_context(
    expr: &Expr,
    target: TextRange,
    parent_is_collection: bool,
    parent_is_blocked: bool,
) -> Option<(bool, bool)> {
    if matches!(expr, Expr::StringLiteral(_) | Expr::BytesLiteral(_)) {
        return (expr.range() == target).then_some((parent_is_collection, parent_is_blocked));
    }
    let child_is_collection = match expr {
        Expr::Call(_) | Expr::List(_) | Expr::Set(_) | Expr::Tuple(_) => true,
        Expr::BinOp(binary) => binary.op == Operator::Add,
        _ => false,
    };
    let child_is_blocked = parent_is_blocked
        || matches!(expr, Expr::Attribute(_))
        || matches!(expr, Expr::BinOp(binary) if binary.op != Operator::Add);
    for child in child_exprs(expr) {
        if let Some(context) =
            find_string_context(child, target, child_is_collection, child_is_blocked)
        {
            return Some(context);
        }
    }
    None
}
