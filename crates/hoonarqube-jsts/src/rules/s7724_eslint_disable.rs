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
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

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
        assert_eq!(issue.range.end.column, "// eslint-disable-next-line".len() as u32);
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
