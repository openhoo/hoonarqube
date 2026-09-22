use super::walker::ReactCollector;
use crate::rules::shared::{jsx_element_tag, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::{JSXAttributeValue, JSXChild, JSXElement};
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6772`: inline siblings separated only by collapsible whitespace.
    /// Explicit separation — a `{" "}`/`&nbsp;` text node or a decorative
    /// separator element such as `<span aria-hidden="true">·</span>` —
    /// already makes the intent unambiguous and is not flagged (#821).
    pub(crate) fn check_whitespace_only_gaps(&mut self, children: &[JSXChild<'_>]) {
        for window in children.windows(3) {
            let [first, middle, last] = window else {
                continue;
            };
            let (Some(first_element), Some(last_element)) =
                (jsx_child_element(first), jsx_child_element(last))
            else {
                continue;
            };
            let (Some(first_tag), Some(last_tag)) = (
                jsx_element_tag(&first_element.opening_element.name),
                jsx_element_tag(&last_element.opening_element.name),
            ) else {
                continue;
            };
            if !INLINE_TAGS.contains(&first_tag) || !INLINE_TAGS.contains(&last_tag) {
                continue;
            }
            if is_separator_element(first_element) || is_separator_element(last_element) {
                continue;
            }
            if let JSXChild::Text(text) = middle
                && !text.value.is_empty()
                && text.value.chars().all(is_collapsible_whitespace)
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

/// HTML whitespace that collapses under JSX rendering. `&nbsp;`
/// (`\u{a0}`) and friends are explicit, non-collapsing separation.
fn is_collapsible_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '\r' | '\u{0b}' | '\u{0c}')
}

/// Decorative separator elements (`<span aria-hidden="true">·</span>`)
/// make the gap between inline siblings explicit (#821).
fn is_separator_element(element: &JSXElement<'_>) -> bool {
    let Some(attribute) = jsx_find_attribute(&element.opening_element, "aria-hidden") else {
        return false;
    };
    match &attribute.value {
        // Bare `aria-hidden` means `true` in JSX.
        None => true,
        Some(JSXAttributeValue::StringLiteral(literal)) => literal.value == "true",
        Some(JSXAttributeValue::ExpressionContainer(container)) => matches!(
            container.expression.as_expression(),
            Some(oxc_ast::ast::Expression::BooleanLiteral(literal)) if literal.value
        ),
        _ => false,
    }
}

/// Tags whose adjacent collapsible whitespace behaves inconsistently
/// (`S6772`).
const INLINE_TAGS: [&str; 36] = [
    "a", "abbr", "b", "bdi", "bdo", "br", "button", "cite", "code", "data", "dfn", "em", "i",
    "img", "input", "kbd", "label", "mark", "q", "rp", "rt", "ruby", "s", "samp", "select", "slot",
    "small", "span", "strong", "sub", "sup", "time", "u", "textarea", "var", "wbr",
];

/// Element behind a child position, if it is a plain element.
fn jsx_child_element<'a>(child: &'a JSXChild<'a>) -> Option<&'a JSXElement<'a>> {
    match child {
        JSXChild::Element(element) => Some(element),
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

    /// #821: the reported fixture — explicit `{" "}` inside the first
    /// element and a decorative separator element between the siblings.
    #[test]
    fn s6772_allows_explicit_expression_and_separator_element() {
        let report = analyze(
            PathBuf::from("summary.tsx"),
            concat!(
                "export function Summary({ total }: { total: number }) {\n",
                "  return (\n",
                "    <p>\n",
                "      <strong>\n",
                "        {total}{\" \"}\n",
                "        {total === 1 ? \"item\" : \"items\"}\n",
                "      </strong>\n",
                "      <span aria-hidden=\"true\">·</span>\n",
                "    </p>\n",
                "  );\n",
                "}\n",
            ),
            JstsLanguage::TypeScript,
            &no_header_options(),
        );
        assert_eq!(count_key(&report_keys(&report), "typescript:S6772"), 0);
    }

    /// #821: `{" "}` and `&nbsp;` are explicit separation, not collapsible
    /// whitespace.
    #[test]
    fn s6772_allows_explicit_space_expression_and_nbsp() {
        let expression = jsx_keys("const el = <div><span>a</span>{\" \"}<b>c</b></div>;\n");
        assert_eq!(count_key(&expression, "javascript:S6772"), 0);
        let spaced_expression =
            jsx_keys("const el = <div><span>a</span> {\" \"} <b>c</b></div>;\n");
        assert_eq!(count_key(&spaced_expression, "javascript:S6772"), 0);
        let nbsp = jsx_keys("const el = <div><span>a</span>&nbsp;<b>c</b></div>;\n");
        assert_eq!(count_key(&nbsp, "javascript:S6772"), 0);
        let nbsp_spaced = jsx_keys("const el = <div><span>a</span> &nbsp; <b>c</b></div>;\n");
        assert_eq!(count_key(&nbsp_spaced, "javascript:S6772"), 0);
    }

    /// #821: decorative separator elements make the gap explicit in either
    /// sibling position and under every `aria-hidden` spelling.
    #[test]
    fn s6772_allows_separator_elements() {
        for markup in [
            "<div><span>a</span> <span aria-hidden=\"true\">·</span></div>",
            "<div><span aria-hidden=\"true\">·</span> <b>c</b></div>",
            "<div><span>a</span> <span aria-hidden>·</span></div>",
            "<div><span>a</span> <span aria-hidden={true}>·</span></div>",
        ] {
            let findings = jsx_keys(&format!("const el = {markup};\n"));
            assert_eq!(count_key(&findings, "javascript:S6772"), 0, "{markup}");
        }
        // `aria-hidden="false"` is not a decorative separator.
        let visible = jsx_keys(
            "const el = <div><span>a</span> <span aria-hidden=\"false\">·</span></div>;\n",
        );
        assert_eq!(count_key(&visible, "javascript:S6772"), 1);
    }
}
