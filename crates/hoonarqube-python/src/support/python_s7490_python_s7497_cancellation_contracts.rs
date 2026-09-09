// --- python:S7490 / python:S7497 — cancellation contracts

use crate::engine::rx::RxUnit;
use crate::support::{
    child_bodies, child_exprs, dotted_name_in, for_each_expr, stmt_exprs, to_u32,
};
use ruff_python_ast::{Expr, Stmt};
use ruff_text_size::TextSize;

#[derive(Clone, Copy, Default)]
struct LoopExits {
    break_exit: bool,
    continue_exit: bool,
}

#[derive(Clone, Copy, Default)]
struct CancellationFlow {
    fallthrough: bool,
    handled_exit: bool,
    unhandled_exit: bool,
    loop_exits: LoopExits,
}

impl CancellationFlow {
    fn merge(&mut self, other: Self) {
        self.fallthrough |= other.fallthrough;
        self.handled_exit |= other.handled_exit;
        self.unhandled_exit |= other.unhandled_exit;
        self.loop_exits.break_exit |= other.loop_exits.break_exit;
        self.loop_exits.continue_exit |= other.loop_exits.continue_exit;
    }
}

pub(crate) fn suite_propagates_cancellation(suite: &[Stmt]) -> bool {
    let flow = sequence_flow(suite);
    flow.handled_exit && !flow.fallthrough && !flow.unhandled_exit
}

fn sequence_flow(suite: &[Stmt]) -> CancellationFlow {
    let mut result = CancellationFlow {
        fallthrough: true,
        ..CancellationFlow::default()
    };
    for statement in suite {
        if !result.fallthrough {
            break;
        }
        let next = statement_flow(statement);
        let previous_handled = result.handled_exit;
        let previous_unhandled = result.unhandled_exit;
        let previous_break = result.loop_exits.break_exit;
        let previous_continue = result.loop_exits.continue_exit;
        result = CancellationFlow {
            fallthrough: next.fallthrough,
            handled_exit: previous_handled || next.handled_exit,
            unhandled_exit: previous_unhandled || next.unhandled_exit,
            loop_exits: LoopExits {
                break_exit: previous_break || next.loop_exits.break_exit,
                continue_exit: previous_continue || next.loop_exits.continue_exit,
            },
        };
    }
    result
}

fn statement_flow(statement: &Stmt) -> CancellationFlow {
    if statement_contains_uncancel(statement) {
        return CancellationFlow {
            handled_exit: true,
            ..CancellationFlow::default()
        };
    }
    match statement {
        Stmt::Raise(_) => CancellationFlow {
            handled_exit: true,
            ..CancellationFlow::default()
        },
        Stmt::Return(_) => CancellationFlow {
            unhandled_exit: true,
            ..CancellationFlow::default()
        },
        Stmt::Break(_) => CancellationFlow {
            loop_exits: LoopExits {
                break_exit: true,
                ..LoopExits::default()
            },
            ..CancellationFlow::default()
        },
        Stmt::Continue(_) => CancellationFlow {
            loop_exits: LoopExits {
                continue_exit: true,
                ..LoopExits::default()
            },
            ..CancellationFlow::default()
        },
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => CancellationFlow {
            fallthrough: true,
            ..CancellationFlow::default()
        },
        Stmt::If(if_stmt) => if_flow(if_stmt),
        Stmt::While(while_stmt) => loop_flow(
            while_stmt.test.as_ref(),
            &while_stmt.body,
            &while_stmt.orelse,
        ),
        Stmt::For(for_stmt) => {
            let body = sequence_flow(&for_stmt.body);
            let orelse = sequence_flow(&for_stmt.orelse);
            let mut result = body;
            result.merge(orelse);
            result.fallthrough = body.loop_exits.break_exit || orelse.fallthrough;
            result.loop_exits.break_exit = false;
            result.loop_exits.continue_exit = false;
            result
        }
        Stmt::Try(try_stmt) => {
            let body = sequence_flow(&try_stmt.body);
            let mut incoming = body;
            if body.fallthrough && !try_stmt.orelse.is_empty() {
                incoming.fallthrough = false;
                incoming.merge(sequence_flow(&try_stmt.orelse));
            }
            for handler in &try_stmt.handlers {
                let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
                incoming.merge(sequence_flow(&handler.body));
            }
            if try_stmt.finalbody.is_empty() {
                incoming
            } else {
                compose_finally(incoming, sequence_flow(&try_stmt.finalbody))
            }
        }
        Stmt::Match(_) => {
            let mut result = CancellationFlow::default();
            for body in child_bodies(statement) {
                result.merge(sequence_flow(body));
            }
            // No case may match.
            result.fallthrough = true;
            result
        }
        _ => {
            let bodies = child_bodies(statement);
            if bodies.is_empty() {
                return CancellationFlow {
                    fallthrough: true,
                    ..CancellationFlow::default()
                };
            }
            let mut result = CancellationFlow::default();
            for body in bodies {
                result.merge(sequence_flow(body));
            }
            result
        }
    }
}

fn if_flow(if_stmt: &ruff_python_ast::StmtIf) -> CancellationFlow {
    let mut result = CancellationFlow::default();
    let mut remaining = true;
    if !is_false_literal(if_stmt.test.as_ref()) {
        result.merge(sequence_flow(&if_stmt.body));
        if is_true_literal(if_stmt.test.as_ref()) {
            remaining = false;
        }
    }
    for clause in &if_stmt.elif_else_clauses {
        if !remaining {
            break;
        }
        match clause.test.as_ref() {
            Some(test) if is_false_literal(test) => {}
            Some(test) => {
                result.merge(sequence_flow(&clause.body));
                if is_true_literal(test) {
                    remaining = false;
                }
            }
            None => {
                result.merge(sequence_flow(&clause.body));
                remaining = false;
            }
        }
    }
    if remaining {
        // A non-constant condition can select no branch.
        result.fallthrough = true;
    }
    result
}

fn loop_flow(test: &Expr, body: &[Stmt], orelse: &[Stmt]) -> CancellationFlow {
    if is_false_literal(test) {
        return sequence_flow(orelse);
    }
    let body_flow = sequence_flow(body);
    if is_true_literal(test) {
        let mut result = body_flow;
        result.fallthrough = body_flow.loop_exits.break_exit;
        result.loop_exits.break_exit = false;
        result.loop_exits.continue_exit = false;
        return result;
    }
    let orelse_flow = sequence_flow(orelse);
    let mut result = body_flow;
    result.merge(orelse_flow);
    result.fallthrough = body_flow.loop_exits.break_exit || orelse_flow.fallthrough;
    result.loop_exits.break_exit = false;
    result.loop_exits.continue_exit = false;
    result
}

fn compose_finally(incoming: CancellationFlow, final_flow: CancellationFlow) -> CancellationFlow {
    let has_incoming = incoming.fallthrough
        || incoming.handled_exit
        || incoming.unhandled_exit
        || incoming.loop_exits.break_exit
        || incoming.loop_exits.continue_exit;
    if !has_incoming {
        return CancellationFlow::default();
    }
    let mut result = CancellationFlow {
        handled_exit: final_flow.handled_exit,
        unhandled_exit: final_flow.unhandled_exit,
        loop_exits: LoopExits {
            break_exit: final_flow.loop_exits.break_exit,
            continue_exit: final_flow.loop_exits.continue_exit,
        },
        ..CancellationFlow::default()
    };
    if final_flow.fallthrough {
        result.merge(incoming);
    }
    result
}

fn statement_contains_uncancel(statement: &Stmt) -> bool {
    if !matches!(
        statement,
        Stmt::Expr(_)
            | Stmt::Assign(_)
            | Stmt::AugAssign(_)
            | Stmt::AnnAssign(_)
            | Stmt::Return(_)
            | Stmt::Assert(_)
    ) {
        return false;
    }
    stmt_exprs(statement)
        .into_iter()
        .any(expr_contains_uncancel)
}

fn expr_contains_uncancel(expression: &Expr) -> bool {
    if is_uncancel_call(expression) {
        return true;
    }
    match expression {
        Expr::BoolOp(boolean) => boolean_contains_uncancel(&boolean.values, boolean.op),
        Expr::If(condition) => {
            if expr_contains_uncancel(&condition.test) {
                true
            } else {
                match constant_truth(&condition.test) {
                    Some(true) => expr_contains_uncancel(&condition.body),
                    Some(false) => expr_contains_uncancel(&condition.orelse),
                    None => {
                        expr_contains_uncancel(&condition.body)
                            && expr_contains_uncancel(&condition.orelse)
                    }
                }
            }
        }
        Expr::ListComp(comp) => first_iterator_uncancels(&comp.generators),
        Expr::SetComp(comp) => first_iterator_uncancels(&comp.generators),
        Expr::DictComp(comp) => first_iterator_uncancels(&comp.generators),
        Expr::Generator(comp) => first_iterator_uncancels(&comp.generators),
        Expr::Compare(compare) => {
            expr_contains_uncancel(&compare.left)
                || compare
                    .comparators
                    .first()
                    .is_some_and(expr_contains_uncancel)
        }
        Expr::Lambda(_) => {
            let mut children = child_exprs(expression);
            children.pop();
            children.into_iter().any(expr_contains_uncancel)
        }
        _ => child_exprs(expression)
            .into_iter()
            .any(expr_contains_uncancel),
    }
}

fn boolean_contains_uncancel(values: &[Expr], operator: ruff_python_ast::BoolOp) -> bool {
    for value in values {
        if expr_contains_uncancel(value) {
            return true;
        }
        let required_truth = operator == ruff_python_ast::BoolOp::And;
        if constant_truth(value) != Some(required_truth) {
            break;
        }
    }
    false
}

fn first_iterator_uncancels(generators: &[ruff_python_ast::Comprehension]) -> bool {
    generators
        .first()
        .is_some_and(|generator| expr_contains_uncancel(&generator.iter))
}

fn constant_truth(expression: &Expr) -> Option<bool> {
    match expression {
        Expr::BooleanLiteral(literal) => Some(literal.value),
        Expr::BoolOp(boolean) => {
            let values = boolean.values.iter().map(constant_truth);
            let values: Option<Vec<bool>> = values.collect();
            values.map(|values| match boolean.op {
                ruff_python_ast::BoolOp::And => values.into_iter().all(|value| value),
                ruff_python_ast::BoolOp::Or => values.into_iter().any(|value| value),
            })
        }
        _ => None,
    }
}

fn is_uncancel_call(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::Call(call)
            if matches!(
                call.func.as_ref(),
                Expr::Attribute(attribute) if attribute.attr.as_str() == "uncancel"
            )
    )
}

fn is_false_literal(expression: &Expr) -> bool {
    matches!(expression, Expr::BooleanLiteral(literal) if !literal.value)
}

fn is_true_literal(expression: &Expr) -> bool {
    matches!(expression, Expr::BooleanLiteral(literal) if literal.value)
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
fn decode_unknown_escape(
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
        return close + 3;
    }
    let ch = rest.chars().next().unwrap_or('\\');
    push('\\', backslash);
    push(ch, backslash + 1);
    1 + ch.len_utf8()
}

/// String-level octal escape (`\0` … `\777`); the produced character is
/// flagged for python:S6537.
fn decode_octal_escape(
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
fn decode_hex_escape(
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
    let digits: String = body[backslash + 2..].chars().take(width).collect();
    if digits.chars().count() == width
        && digits.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(value) = u32::from_str_radix(&digits, 16)
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
            if dotted_name_in(e, &["re.X", "re.VERBOSE"]) {
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
