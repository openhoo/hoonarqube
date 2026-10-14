use super::collectors::DuplicationCollector;
use crate::support::RuleScope;
use oxc_span::Span;

/// `S1067`: expressions carrying more conditional operators than this are
/// flagged (frozen catalog default of the `max` parameter).
const MAX_CONDITION_OPERATORS: usize = 3;

impl DuplicationCollector<'_> {
    /// `S1067`: an expression tree with more conditional operators than the
    /// catalog maximum. `operators` counts `&&`/`||`/`??` and ternary `?`
    /// tokens accumulated by the collector's scope tracking; unary `!` is
    /// not a boolean operator for this rule.
    pub(crate) fn report_condition_operators(&mut self, operators: u32, span: Span) {
        let operators = usize::try_from(operators).unwrap_or(usize::MAX);
        if operators > MAX_CONDITION_OPERATORS {
            self.sink.emit_span(
                RuleScope::Both,
                "S1067",
                &format!(
                    "Reduce the number of conditional operators ({operators}) used in the expression (maximum allowed {MAX_CONDITION_OPERATORS})."
                ),
                span,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{issue, js, ts};

    fn assert_reference_messages(key: &str, analyze: fn(&str) -> hoonarqube_ir::FileReport) {
        // The four-operator case and its range are retained real SonarJS
        // controls. The second message also occurs in the retained OSS run.
        for (source, expected) in [
            (
                "while (a && !b && c || d || e) {\n  g();\n}\n",
                issue(
                    key,
                    "Reduce the number of conditional operators (4) used in the expression (maximum allowed 3).",
                    (1, 7),
                    (1, 29),
                ),
            ),
            (
                "const value = a && b && c && d && e && f && g && h && i && j && k && l;\n",
                issue(
                    key,
                    "Reduce the number of conditional operators (11) used in the expression (maximum allowed 3).",
                    (1, 14),
                    (1, 70),
                ),
            ),
        ] {
            let report = analyze(source);
            let findings: Vec<_> = report
                .issues
                .iter()
                .filter(|finding| finding.rule_key == key)
                .collect();
            assert_eq!(findings, vec![&expected]);
        }
    }

    #[test]
    fn s1067_javascript_messages_and_ranges_match_sonarjs() {
        assert_reference_messages("javascript:S1067", js);
    }

    #[test]
    fn s1067_typescript_messages_and_ranges_match_sonarjs() {
        assert_reference_messages("typescript:S1067", ts);
    }
}
