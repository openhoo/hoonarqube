use super::walker::{ReactCollector, jsx_element_tag};
use crate::support::RuleScope;
use oxc_ast::ast::JSXChild;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6772`: inline siblings separated only by collapsible whitespace.
    pub(crate) fn check_whitespace_only_gaps(&mut self, children: &[JSXChild<'_>]) {
        for window in children.windows(3) {
            let [first, middle, last] = window else {
                continue;
            };
            let (Some(first_tag), Some(last_tag)) =
                (jsx_child_element_tag(first), jsx_child_element_tag(last))
            else {
                continue;
            };
            if !INLINE_TAGS.contains(&first_tag) || !INLINE_TAGS.contains(&last_tag) {
                continue;
            }
            if let JSXChild::Text(text) = middle
                && !text.value.is_empty()
                && text.value.trim().is_empty()
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6772",
                    "Whitespace between these inline elements collapses inconsistently; make the separation explicit.",
                    text.span(),
                );
            }
        }
    }
}

/// Tags whose adjacent collapsible whitespace behaves inconsistently
/// (`S6772`).
pub(crate) const INLINE_TAGS: [&str; 36] = [
    "a", "abbr", "b", "bdi", "bdo", "br", "button", "cite", "code", "data", "dfn", "em", "i",
    "img", "input", "kbd", "label", "mark", "q", "rp", "rt", "ruby", "s", "samp", "select", "slot",
    "small", "span", "strong", "sub", "sup", "time", "u", "textarea", "var", "wbr",
];

/// Element tag behind a child position, if it is a plain element.
pub(crate) fn jsx_child_element_tag<'a>(child: &'a JSXChild<'a>) -> Option<&'a str> {
    match child {
        JSXChild::Element(element) => jsx_element_tag(&element.opening_element.name),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6772_flags_whitespace_only_gap_between_inline_siblings() {
        let findings = jsx_keys("const el = <div><span>a</span> <b>c</b></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6772"), 1);
    }

    #[test]
    fn s6772_allows_gap_between_block_elements() {
        let findings = jsx_keys("const el = <div><p>a</p> <p>b</p></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6772"), 0);
    }

    #[test]
    fn s6772_flags_newline_gap_between_inline_siblings() {
        let findings = jsx_keys("const el = <div><span>a</span>\n<b>c</b></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6772"), 1);
    }

    #[test]
    fn s6772_allows_explicit_text_separation() {
        let findings = jsx_keys("const el = <div><span>a</span> text <b>c</b></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6772"), 0);
    }
}
