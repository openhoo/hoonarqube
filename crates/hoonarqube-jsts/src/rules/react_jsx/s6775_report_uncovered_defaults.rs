use super::walker::{PropKind, ReactCollector};
use crate::support::RuleScope;

impl ReactCollector<'_> {
    /// `S6775` post-pass: flags `defaultProps` entries without a matching
    /// `isRequired` declaration.
    pub(crate) fn report_uncovered_defaults(&mut self) {
        let mut uncovered = Vec::new();
        for (component, defaults) in &self.prop_defaults {
            let Some(declarations) = self.prop_declarations.get(component) else {
                continue;
            };
            for (property, span) in defaults {
                if declarations.get(property) != Some(&PropKind::Required) {
                    uncovered.push(*span);
                }
            }
        }
        for span in uncovered {
            self.sink.emit_span(
                RuleScope::Both,
                "S6775",
                "'defaultProps' entry without an 'isRequired' 'propTypes' declaration hides missing-prop mistakes.",
                span,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6775_flags_default_for_optional_prop() {
        let findings = js_keys("C.propTypes = {a: PropTypes.string};\nC.defaultProps = {a: 'x'};\n");
        assert_eq!(count_key(&findings, "javascript:S6775"), 1);
    }

    #[test]
    fn s6775_allows_default_for_required_prop() {
        let findings = js_keys(
            "C.propTypes = {a: PropTypes.string.isRequired};\nC.defaultProps = {a: 'x'};\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6775"), 0);
    }

    #[test]
    fn s6775_ignores_defaults_without_any_declarations() {
        let findings = js_keys("C.defaultProps = {a: 'x'};\n");
        assert_eq!(count_key(&findings, "javascript:S6775"), 0);
    }
}
