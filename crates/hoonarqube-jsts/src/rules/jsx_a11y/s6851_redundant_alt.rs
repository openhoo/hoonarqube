use super::walker::{A11yCollector, attribute_static_value, jsx_element_tag, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6851`: alt text repeating the file name or a filler word.
    pub(crate) fn check_redundant_alt(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("img") {
            return;
        }
        let Some(alt_attribute) = jsx_find_attribute(&element.opening_element, "alt") else {
            return;
        };
        let Some(alt) = attribute_static_value(alt_attribute) else {
            return;
        };
        let normalized = alt.trim().to_lowercase();
        let source_stem = jsx_find_attribute(&element.opening_element, "src")
            .and_then(attribute_static_value)
            .and_then(|source| source.rsplit('/').next())
            .and_then(|name| name.rsplit_once('.').map(|(stem, _)| stem))
            .map(str::to_lowercase);
        if REDUNDANT_ALT_WORDS.contains(&normalized.as_str())
            || source_stem.as_deref() == Some(normalized.as_str())
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6851",
                "Redundant 'alt' text; describe the image purpose instead.",
                alt_attribute.span(),
            );
        }
    }
}

/// Redundant image alt texts (`S6851`).
pub(crate) const REDUNDANT_ALT_WORDS: [&str; 6] =
    ["image", "photo", "picture", "grafik", "bild", "logo"];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6851_flags_filler_words_in_alt_text() {
        let filler = jsx_keys("const el = <img src=\"team.jpg\" alt=\"photo\"/>;\n");
        assert_eq!(count_key(&filler, "javascript:S6851"), 1);
    }

    #[test]
    fn s6851_flags_alt_repeating_the_file_stem() {
        let stem_match = jsx_keys("const el = <img src=\"/img/banner.svg\" alt=\"Banner\"/>;\n");
        assert_eq!(count_key(&stem_match, "javascript:S6851"), 1);
    }

    #[test]
    fn s6851_accepts_descriptive_dynamic_and_missing_alts() {
        let descriptive =
            jsx_keys("const el = <img src=\"team.jpg\" alt=\"Engineering team offsite\"/>;\n");
        assert_eq!(count_key(&descriptive, "javascript:S6851"), 0);

        let dynamic =
            jsx_keys("let text = 'photo';\nconst el = <img src=\"a.png\" alt={text}/>;\n");
        assert_eq!(count_key(&dynamic, "javascript:S6851"), 0);

        let missing_alt = jsx_keys("const el = <img src=\"team.jpg\"/>;\n");
        assert_eq!(count_key(&missing_alt, "javascript:S6851"), 0);
    }
}
