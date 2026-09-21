use super::collectors::language_tag_is_valid;
use super::walker::{
    A11yCollector, attribute_static_value, jsx_element_tag, jsx_find_attribute,
    jsx_has_spread_attribute,
};
use crate::support::RuleScope;
use oxc_ast::ast::{Expression, JSXAttribute, JSXAttributeValue, JSXElement};
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S5254`: the root `<html>` element needs a valid language tag.
    pub(crate) fn check_html_lang(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("html")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let Some(lang) = jsx_find_attribute(&element.opening_element, "lang") else {
            self.emit_invalid_lang(element);
            return;
        };
        if lang_value_is_reportable(lang) {
            self.emit_invalid_lang(element);
        }
    }

    fn emit_invalid_lang(&mut self, element: &JSXElement<'_>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S5254",
            "Give the <html> element a valid 'lang' attribute.",
            element.opening_element.span(),
        );
    }
}

/// Whether a present `lang` attribute is proven invalid (`S5254`). Static
/// string values must be valid BCP-47 subset tags; statically falsy
/// expressions (`{undefined}`, `{null}`, `{false}`, `{0}`, `{""}`) are known
/// to produce no usable tag. Any other expression value is unknown at
/// analysis time and stays unreported, matching the reference.
fn lang_value_is_reportable(attribute: &JSXAttribute<'_>) -> bool {
    match attribute.value.as_ref() {
        Some(JSXAttributeValue::StringLiteral(_)) => {
            !attribute_static_value(attribute).is_some_and(language_tag_is_valid)
        }
        Some(JSXAttributeValue::ExpressionContainer(container)) => {
            match container.expression.as_expression() {
                Some(Expression::StringLiteral(_)) => {
                    !attribute_static_value(attribute).is_some_and(language_tag_is_valid)
                }
                Some(Expression::TemplateLiteral(template)) if template.expressions.is_empty() => {
                    // A static template literal is a known string value.
                    template
                        .quasis
                        .first()
                        .and_then(|quasi| quasi.value.cooked.as_ref())
                        .is_none_or(|cooked| !language_tag_is_valid(cooked))
                }
                Some(expression) => expression_is_statically_falsy(expression),
                // `{}` cannot produce a value.
                None => true,
            }
        }
        // Bare `lang` implies `lang={true}` upstream, which is not reported;
        // `<html lang=<div/>` is not a string value. Both stay unknown.
        None | Some(_) => false,
    }
}

/// Whether an expression is statically known to evaluate to a falsy value
/// (`undefined`, `null`, `false`, `0`, `""`), which the reference
/// `html-has-lang` reports as a missing `lang` value.
fn expression_is_statically_falsy(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::NullLiteral(_) => true,
        Expression::BooleanLiteral(literal) => !literal.value,
        Expression::NumericLiteral(literal) => literal.value == 0.0,
        Expression::Identifier(identifier) => identifier.name == "undefined",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s5254_flags_html_elements_with_missing_or_invalid_lang() {
        let missing = jsx_keys("const el = <html><body/></html>;\n");
        assert_eq!(count_key(&missing, "javascript:S5254"), 1);

        let invalid = jsx_keys("const el = <html lang=\"english!\"><body/></html>;\n");
        assert_eq!(count_key(&invalid, "javascript:S5254"), 1);
    }

    #[test]
    fn s5254_accepts_valid_language_tags() {
        let region = jsx_keys("const el = <html lang=\"de-DE\"><body/></html>;\n");
        assert_eq!(count_key(&region, "javascript:S5254"), 0);

        let base = jsx_keys("const el = <html lang=\"fr\"><body/></html>;\n");
        assert_eq!(count_key(&base, "javascript:S5254"), 0);
    }

    #[test]
    fn s5254_skips_spread_html_and_other_tags() {
        let spread = jsx_keys("const el = <html {...props}><body/></html>;\n");
        assert_eq!(count_key(&spread, "javascript:S5254"), 0);

        let other_tag = jsx_keys("const el = <div lang=\"e\"/>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S5254"), 0);
    }

    #[test]
    fn s5254_accepts_expression_lang_values() {
        // An expression value is unknown at analysis time, not proven invalid.
        let identifier = jsx_keys("const el = <html lang={languageCode}><body/></html>;\n");
        assert_eq!(count_key(&identifier, "javascript:S5254"), 0);

        let member = jsx_keys("const el = <html lang={config.lang}><body/></html>;\n");
        assert_eq!(count_key(&member, "javascript:S5254"), 0);

        let call = jsx_keys("const el = <html lang={getLang()}><body/></html>;\n");
        assert_eq!(count_key(&call, "javascript:S5254"), 0);
    }

    #[test]
    fn s5254_flags_known_invalid_values() {
        // Known-invalid values stay reportable, unlike unknown expressions.
        let undefined = jsx_keys("const el = <html lang={undefined}><body/></html>;\n");
        assert_eq!(count_key(&undefined, "javascript:S5254"), 1);

        let null = jsx_keys("const el = <html lang={null}><body/></html>;\n");
        assert_eq!(count_key(&null, "javascript:S5254"), 1);

        let empty = jsx_keys("const el = <html lang=\"\"><body/></html>;\n");
        assert_eq!(count_key(&empty, "javascript:S5254"), 1);

        let invalid_literal = jsx_keys("const el = <html lang={\"english!\"}><body/></html>;\n");
        assert_eq!(count_key(&invalid_literal, "javascript:S5254"), 1);
    }

    #[test]
    fn s5254_evaluates_static_template_literals() {
        let valid = jsx_keys("const el = <html lang={`en`}><body/></html>;\n");
        assert_eq!(count_key(&valid, "javascript:S5254"), 0);

        let invalid = jsx_keys("const el = <html lang={`english!`}><body/></html>;\n");
        assert_eq!(count_key(&invalid, "javascript:S5254"), 1);
    }
}
