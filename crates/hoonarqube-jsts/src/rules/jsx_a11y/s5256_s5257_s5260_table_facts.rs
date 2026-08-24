use super::walker::{A11yCollector, SubtreeFacts, TableMarkers, explicit_role, jsx_element_tag};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S5256`, `S5257`, and `S5260`: header structure inside tables.
    pub(crate) fn check_table_facts(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("table") {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        let presentation_role = explicit_role(&element.opening_element)
            .is_some_and(|role| role == "presentation" || role == "none");
        if facts.table_markers != TableMarkers::Headers {
            self.sink.emit_span(
                RuleScope::Both,
                "S5256",
                "Add header cells (<th> or <thead>) to this table.",
                element.opening_element.span(),
            );
            if facts.table_markers == TableMarkers::Plain && !presentation_role {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5257",
                    "Mark this layout table with role=\"presentation\" or give it real headers.",
                    element.opening_element.span(),
                );
            }
        }
        for (span, tokens) in &facts.header_references {
            if tokens.iter().any(|token| !facts.header_ids.contains(token)) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5260",
                    "This 'headers' reference does not match any <th id> in the table.",
                    *span,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s5256_and_s5257_flag_plain_layout_tables_together() {
        let plain = jsx_keys("const el = <table><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&plain, "javascript:S5256"), 1);
        assert_eq!(count_key(&plain, "javascript:S5257"), 1);
    }

    #[test]
    fn s5256_still_requires_headers_when_presentation_or_captioned() {
        let presentation =
            jsx_keys("const el = <table role=\"presentation\"><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&presentation, "javascript:S5256"), 1);
        assert_eq!(count_key(&presentation, "javascript:S5257"), 0);

        let captioned =
            jsx_keys("const el = <table><caption>t</caption><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&captioned, "javascript:S5257"), 0);
    }

    #[test]
    fn s5256_accepts_thead_sections() {
        let thead = jsx_keys(
            "const el = <table><thead><tr><th>Name</th></tr></thead><tbody><tr><td>x</td></tr></tbody></table>;\n",
        );
        assert_eq!(count_key(&thead, "javascript:S5256"), 0);
        assert_eq!(count_key(&thead, "javascript:S5257"), 0);
    }

    #[test]
    fn s5260_flags_each_dangling_token_in_a_reference() {
        let dangling = jsx_keys(
            "const el = <table><tr><th id=\"a\"/><td headers=\"a missing\"/></tr></table>;\n",
        );
        assert_eq!(count_key(&dangling, "javascript:S5260"), 1);

        let resolved =
            jsx_keys("const el = <table><tr><th id=\"a\"/><td headers=\"a\"/></tr></table>;\n");
        assert_eq!(count_key(&resolved, "javascript:S5260"), 0);
    }
}
