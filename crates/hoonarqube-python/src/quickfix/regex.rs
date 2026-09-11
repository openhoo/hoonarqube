use super::{Alternative, alt, issue_range, text_edit};
use crate::support::{dotted_name, dotted_name_in, for_each_expr, keyword_value};
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// Returns the pinned `SonarPython` alternatives for the three S6353 shapes.
///
/// Detector spans are deliberately trusted only together with their pinned
/// issue message: a full character-class span, an equal-range span, and the
/// greedy-star quantifier span have different projections.
pub(super) fn alternatives(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &crate::engine::file_context::FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    if issue.rule_key != "python:S6353" {
        return Vec::new();
    }
    let range = issue_range(issue, index, source);
    let text = &source[range];

    if let Some(replacement) = concise_quantifier(text) {
        return vec![alt(
            "s6353-use-concise-quantifier",
            "Use the concise equivalent for this quantifier.",
            vec![text_edit(index, source, range, replacement)],
        )];
    }
    if text.starts_with('[') && text.ends_with(']') {
        let (ascii, dotall) = effective_flags(parsed, file_ctx, range);
        if let Some(replacement) =
            issue_message_replacement(&issue.message, "syntax '", "' instead")
                .filter(|replacement| matches!(*replacement, "\\d" | "\\D" | "\\w" | "\\W" | "."))
                .filter(
                    |replacement| {
                        if *replacement == "." { dotall } else { ascii }
                    },
                )
        {
            return vec![alt(
                "s6353-use-concise-character-class",
                format!("Replace with \"{replacement}\""),
                vec![text_edit(index, source, range, replacement)],
            )];
        }
    }

    if issue.message.contains("simple character '")
        && let Some(replacement) =
            issue_message_replacement(&issue.message, "simple character '", "' instead")
                .filter(|replacement| !replacement.is_empty() && text.contains('-'))
    {
        return vec![alt(
            "s6353-use-simple-character",
            format!("Replace with \"{replacement}\""),
            vec![text_edit(index, source, range, replacement)],
        )];
    }

    if text.len() > 1
        && text.ends_with('*')
        && issue.message.contains("simple repetition")
        && safe_repetition_span(text)
    {
        return vec![alt(
            "s6353-use-simple-repetition",
            "Replace with \"+\"",
            vec![text_edit(index, source, range, "+")],
        )];
    }

    Vec::new()
}

fn concise_quantifier(text: &str) -> Option<String> {
    let text = text.strip_suffix('?').unwrap_or(text);
    let body = text.strip_prefix('{')?.strip_suffix('}')?;
    let (lower, upper) = body.split_once(',')?;
    if lower == "0" && upper == "1" {
        return Some("?".to_string());
    }
    if lower == "0" && upper.is_empty() {
        return Some("*".to_string());
    }
    if lower == "1" && upper.is_empty() {
        return Some("+".to_string());
    }
    if !lower.is_empty() && lower == upper && lower.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(format!("{{{lower}}}"));
    }
    None
}

fn issue_message_replacement<'a>(message: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let (_, rest) = message.split_once(prefix)?;
    rest.split_once(suffix).map(|(replacement, _)| replacement)
}

fn safe_repetition_span(text: &str) -> bool {
    let Some(atom) = text.strip_suffix('*') else {
        return false;
    };
    if atom.is_empty() || atom.starts_with('(') {
        return false;
    }
    let Some(rest) = atom.strip_prefix('\\') else {
        return true;
    };
    !rest.chars().next().is_some_and(|ch| ch.is_ascii_digit()) && !atom.starts_with("\\g<")
}

fn effective_flags(
    parsed: &Parsed<ModModule>,
    file_ctx: &crate::engine::file_context::FileContext<'_>,
    issue_range: ruff_text_size::TextRange,
) -> (bool, bool) {
    for call in &file_ctx.calls {
        let Some(path) = dotted_name(&call.func) else {
            continue;
        };
        if !crate::support::REGEX_FUNCTIONS.contains(&path.as_str()) {
            continue;
        }
        let pattern = call
            .arguments
            .args
            .first()
            .or_else(|| keyword_value(&call.arguments, "pattern"));
        if !pattern.is_some_and(|expr| expr.range().contains_range(issue_range)) {
            continue;
        }
        let flags = keyword_value(&call.arguments, "flags").or_else(|| {
            let index = match path.as_str() {
                "re.compile" => 1,
                "re.sub" | "re.subn" => 4,
                _ => 2,
            };
            call.arguments.args.get(index)
        });
        let Some(flags) = flags else {
            return (false, false);
        };
        let mut ascii = false;
        let mut dotall = false;
        for_each_expr(flags, &mut |expr| {
            ascii |= dotted_name_in(expr, &["re.ASCII", "re.A"]);
            dotall |= dotted_name_in(expr, &["re.DOTALL", "re.S"]);
        });
        return (ascii, dotall);
    }
    let _ = parsed;
    (false, false)
}
