// --- python:S7490 / python:S7497 — cancellation contracts

use crate::engine::rx::RxUnit;
use crate::support::{child_bodies, dotted_name, for_each_expr, to_u32};
use ruff_python_ast::Stmt;
use ruff_text_size::TextSize;

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
        return close + 4;
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
