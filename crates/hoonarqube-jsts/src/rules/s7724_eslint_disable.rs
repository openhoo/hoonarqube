// Rule module s7724_eslint_disable (generated).
//
// `typescript:S7724` — ESLint disable comments should specify which rules
// to disable. Reference semantics: eslint-plugin-unicorn
// `no-abusive-eslint-disable` on top of ESLint's directive parser: a
// comment whose directive part is exactly `eslint-disable-next-line`,
// `eslint-disable-line`, or `eslint-disable` (block comments only for the
// bare `eslint-disable` form) and whose rule list after the directive
// label is empty is reported with "Specify the rules you want to
// disable.". A rule list is still empty when only a `-- justification`
// follows the label; any rule name keeps the comment silent.
// `eslint-disable-line` directives spanning multiple lines are parser
// problems, not findings, and stay silent. Findings span the whole
// comment.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, ScannedComment, source_slice};
use hoonarqube_ir::Issue;

/// Entry point: `typescript:S7724` broad `ESLint` disable directive check.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    for &comment in &ctx.comments {
        if is_broad_disable(ctx.source, comment) {
            sink.emit_span(
                RuleScope::TsOnly,
                "S7724",
                "Specify the rules you want to disable.",
                comment.token,
            );
        }
    }
    sink.issues
}

/// Whether the comment is an `ESLint` disable directive with an empty rule
/// list, following `ESLint`'s directive parsing: the justification is split
/// on a whitespace-surrounded `--` run first, then the directive label is
/// matched against the comment kind and capabilities.
fn is_broad_disable(source: &str, comment: ScannedComment) -> bool {
    let body = source_slice(source, comment.body);
    let Some((label, rule_list)) = directive_part(body.trim()) else {
        return false;
    };
    match label {
        // A bare `eslint-disable` is a directive only in block comments.
        "eslint-disable" => is_block_comment(source, comment) && rule_list.is_empty(),
        // A multi-line `eslint-disable-line` is a parser problem, not a
        // directive, so it never becomes a finding.
        "eslint-disable-line" => !body.contains('\n') && rule_list.is_empty(),
        _ => rule_list.is_empty(),
    }
}

/// The directive label and its (possibly empty) trimmed rule list, after
/// splitting off a ` -- justification` suffix.
fn directive_part(trimmed: &str) -> Option<(&str, &str)> {
    let part = strip_justification(trimmed);
    for label in [
        "eslint-disable-next-line",
        "eslint-disable-line",
        "eslint-disable",
    ] {
        if let Some(rest) = part.strip_prefix(label)
            && (rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            return Some((label, rest.trim()));
        }
    }
    None
}

/// The part of `trimmed` before the first whitespace-surrounded run of two
/// or more hyphens (`ESLint`'s justification separator `\s-{2,}\s`).
fn strip_justification(trimmed: &str) -> &str {
    for (index, character) in trimmed.char_indices() {
        if !character.is_whitespace() {
            continue;
        }
        let after_character = &trimmed[index + character.len_utf8()..];
        let hyphen_run = after_character.chars().take_while(|c| *c == '-').count();
        if hyphen_run < 2 {
            continue;
        }
        if after_character[hyphen_run..].starts_with(char::is_whitespace) {
            return trimmed[..index].trim_end();
        }
    }
    trimmed
}

fn is_block_comment(source: &str, comment: ScannedComment) -> bool {
    source_slice(source, comment.token).starts_with("/*")
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7724_flags_pinned_zod_broad_next_line_directive() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:610
        // — a broad `// eslint-disable-next-line` above a commented-out
        // emailRegex declaration.
        let source = "// from https://stackoverflow.com/a/46181\n\
                      // eslint-disable-next-line\n\
                      // const emailRegex = /x/;\n\
                      const ok = 1;\n";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7724"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7724")
            .expect("the broad disable directive must be reported");
        assert_eq!(issue.message, "Specify the rules you want to disable.");
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(issue.range.start.column, 0);
        assert_eq!(issue.range.end.line, 2);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("// eslint-disable-next-line".len()).unwrap()
        );
    }

    #[test]
    fn s7724_flags_every_broad_directive_form() {
        let source = "\
/* eslint-disable */
// eslint-disable-line
/* eslint-disable-next-line */
// eslint-disable-next-line -- legacy workaround
// eslint-disable-next-line\t
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7724"), 5);
    }

    #[test]
    fn s7724_specified_rules_and_justified_rules_stay_silent() {
        let silent = "// eslint-disable-next-line no-console\n\
                      // eslint-disable-next-line no-console no-debugger\n\
                      // eslint-disable-next-line no-console -- reason\n\
                      /* eslint-disable no-console */\n\
                      // eslint-disable-line no-restricted-syntax\n";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7724"), 0);
    }

    #[test]
    fn s7724_plain_line_disable_and_non_directives_stay_silent() {
        let silent = "// eslint-disable\n\
                      // eslint-disablefoo\n\
                      // not a directive\n\
                      /* eslint-disable-line\n\
                      spanning lines */\n";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7724"), 0);
    }

    #[test]
    fn s7724_stays_silent_in_javascript_files() {
        let source = "// eslint-disable-next-line\nconst a = 1;\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7724"), 0);
    }
}
