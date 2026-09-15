// Rule module s139_disallowed_comment_pattern (generated).

use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::regex_search;
use crate::support::{IssueSink, RuleScope, ScannedComment, source_slice};
use hoonarqube_ir::Issue;

/// `S139` pins the upstream `line-comment-position` rule in its "above"
/// mode: every `//` comment that follows a token on its own line is
/// reported with the pinned Sonar way message. Exemptions mirror the
/// upstream wrapper: `NOSONAR` (handled by the dedicated `S1291` rule),
/// the `ESLint` default ignore prefixes (`eslint`, `jshint `, `jslint `,
/// `istanbul `, `globals? `, `exported `, `jscs`, `falls? through`), and
/// the catalog `pattern` parameter (default `^\s*[^\s]+$`: single-token
/// notes), matched with search semantics against the comment text.
///
/// Block comments are never reported, and own-line comments (including
/// consecutive comment-only lines) stay clean.
fn check_disallowed_comment_pattern(
    sink: &mut IssueSink,
    source: &str,
    comments: &[ScannedComment],
    comment: &ScannedComment,
    body: &str,
    rules: &RuleOptions,
) {
    if !source[comment.token.start as usize..].starts_with("//") {
        return;
    }
    let line_start = sink.index.line_start(comment.token.start);
    if !code_or_comment_precedes_on_line(source, comments, line_start, comment.token.start) {
        return;
    }
    if body.contains("NOSONAR") || default_ignored_comment(body) {
        return;
    }
    if regex_search(&rules.comment_pattern, body) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S139",
        "Expected comment to be above code.",
        comment.token,
    );
}

/// Whether a real token precedes the comment on its own line. A comment
/// ending on this line is itself a preceding token (`/* c */ // note`),
/// so its presence decides; otherwise only non-whitespace code counts,
/// keeping consecutive own-line comments clean.
fn code_or_comment_precedes_on_line(
    source: &str,
    comments: &[ScannedComment],
    line_start: u32,
    comment_start: u32,
) -> bool {
    let line_start = line_start as usize;
    let comment_start = comment_start as usize;
    if comments
        .iter()
        .filter(|other| (other.token.end as usize) <= comment_start)
        .max_by_key(|other| other.token.end)
        .is_some_and(|previous| (previous.token.end as usize) > line_start)
    {
        return true;
    }
    source[line_start..comment_start]
        .chars()
        .any(|c| !c.is_whitespace())
}

/// `ESLint`'s default ignore patterns for `line-comment-position`
/// (`COMMENTS_IGNORE_PATTERN` plus the fall-through marker).
fn default_ignored_comment(value: &str) -> bool {
    let rest = value.trim_start();
    if rest.starts_with("eslint") || rest.starts_with("jscs") {
        return true;
    }
    for prefix in [
        "jshint", "jslint", "istanbul", "exported", "global", "globals",
    ] {
        if let Some(tail) = rest.strip_prefix(prefix)
            && tail.starts_with(char::is_whitespace)
        {
            return true;
        }
    }
    let body = rest
        .strip_prefix("falls")
        .or_else(|| rest.strip_prefix("fall"));
    if let Some(tail) = body {
        let tail = tail.strip_prefix(' ').unwrap_or(tail);
        return tail.starts_with("through");
    }
    false
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    for comment in &ctx.comments {
        let body = source_slice(ctx.source, comment.body);
        check_disallowed_comment_pattern(
            &mut sink,
            ctx.source,
            &ctx.comments,
            comment,
            body,
            ctx.rules,
        );
    }
    sink.issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn trailing_line_comments_after_code_are_reported() {
        // #391: the dominant express shape — a multi-word trailing note
        // after an object property with a trailing comma.
        let report =
            js("const config = {\n  resave: false, // don't save session if unmodified\n};\n");
        let sites: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S139")
            .map(|issue| (issue.range.start.line, issue.message.as_str()))
            .collect();
        assert_eq!(sites, vec![(2, "Expected comment to be above code.")]);

        let statement = js_keys("let a = 1; // TODO reconsider\n");
        assert_eq!(count_key(&statement, "javascript:S139"), 1);
    }

    #[test]
    fn own_line_comments_stay_clean() {
        let own_line = js_keys("// hack\nlet x = 1;\n");
        assert_eq!(count_key(&own_line, "javascript:S139"), 0);

        // Consecutive own-line comments do not report each other.
        let stacked = js_keys("// first note\n// second note\nlet x = 1;\n");
        assert_eq!(count_key(&stacked, "javascript:S139"), 0);
    }

    #[test]
    fn block_comments_are_never_reported() {
        let trailing_block = js_keys("let x = 1; /* trailing block */\n");
        assert_eq!(count_key(&trailing_block, "javascript:S139"), 0);

        let two_decker = js_keys("let x = 1; /* block */ // deck two\n");
        assert_eq!(count_key(&two_decker, "javascript:S139"), 1);
    }

    #[test]
    fn nosonar_trailing_comments_are_spared_from_s139() {
        // The suppression marker is handled by the dedicated `S1291` rule;
        // the same comment token must not double-report as `S139`.
        let findings = js_keys("let x = 1; // NOSONAR\n");
        assert_eq!(count_key(&findings, "javascript:S139"), 0);
        assert_eq!(count_key(&findings, "javascript:S1291"), 1);
    }

    #[test]
    fn default_ignored_comment_texts_are_exempt() {
        for body in [
            "eslint-disable-line no-console",
            "jshint ignore:line",
            "istanbul ignore next",
            "globals foo",
            "exported bar",
            "jscs",
            "falls through",
            "fallthrough",
        ] {
            let source = format!("let x = 1; // {body}\n");
            assert_eq!(
                count_key(&js_keys(&source), "javascript:S139"),
                0,
                "expected exemption for {body:?}"
            );
        }
    }

    #[test]
    fn catalog_pattern_marks_single_token_comments_legal() {
        // The catalog default `^\s*[^\s]+$` allows single-token notes.
        let single = js_keys("let x = 1; // wat?\n");
        assert_eq!(count_key(&single, "javascript:S139"), 0);

        let empty = js_keys("let x = 1; //\n");
        assert_eq!(count_key(&empty, "javascript:S139"), 1);

        let whitespace_only = js_keys("let a = 1; //   \n");
        assert_eq!(count_key(&whitespace_only, "javascript:S139"), 1);
    }

    #[test]
    fn custom_pattern_allows_matching_comment_texts() {
        let rules = RuleOptions {
            comment_pattern: "TODO".to_string(),
            ..RuleOptions::default()
        };
        let allowed = keys_with_rules("let a = 1; // TODO reconsider\n", &rules);
        assert_eq!(count_key(&allowed, "javascript:S139"), 0);

        let still_flagged = keys_with_rules("let a = 1; // fix this later\n", &rules);
        assert_eq!(count_key(&still_flagged, "javascript:S139"), 1);
    }

    #[test]
    fn trailing_comment_after_block_comment_on_own_line_is_reported() {
        // The block comment's closing delimiter is a token on this line.
        let findings = js_keys("/*\n * header\n */ // note after block\nlet x = 1;\n");
        assert_eq!(count_key(&findings, "javascript:S139"), 1);
    }
}
