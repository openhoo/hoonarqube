use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_ast::ast::JSXText;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6766`: raw quote characters in JSX text nodes. Raw `>` and `}`
    /// never reach the AST (the oxc lexer rejects them; the tolerant parse
    /// recovers with an empty program), so quotes are the flaggable subset.
    pub(crate) fn check_unescaped_entities(&mut self, text: &JSXText<'_>) {
        let unescaped = text
            .value
            .chars()
            .any(|ch| matches!(ch, '>' | '}' | '{' | '"' | '\''));
        if unescaped {
            self.sink.emit_span(
                RuleScope::Both,
                "S6766",
                "Escape this character in JSX text; use an HTML entity instead.",
                text.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6766_flags_raw_apostrophe_in_jsx_text() {
        let findings = jsx_keys("const el = <div>it's here</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6766"), 1);
    }

    #[test]
    fn s6766_allows_plain_jsx_text() {
        let findings = jsx_keys("const el = <div>plain text</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6766"), 0);
    }

    #[test]
    fn s6766_flags_raw_double_quote_in_jsx_text() {
        let findings = jsx_keys("const el = <div>say \"hi\"</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6766"), 1);
    }

    #[test]
    fn s6766_ignores_quotes_inside_attribute_values() {
        let findings = jsx_keys("const el = <div title=\"it's\">text</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6766"), 0);
    }
}
