use super::walker::{ReactCollector, capitalize_first, is_state_setter_name};
use crate::support::RuleScope;
use crate::support::binding_identifier_name;
use crate::support::callee_name;
use oxc_ast::ast::BindingPattern;
use oxc_ast::ast::Expression;
use oxc_ast::ast::VariableDeclarator;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6754`: `useState` destructuring pairs follow the
    /// `[value, setValue]` naming convention.
    pub(crate) fn check_use_state_pair(&mut self, declarator: &VariableDeclarator<'_>) {
        let Some(Expression::CallExpression(call)) = &declarator.init else {
            return;
        };
        if callee_name(call) != Some("useState") {
            return;
        }
        if matches!(&declarator.id, BindingPattern::BindingIdentifier(_)) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6442",
                "Destructure the 'useState' result into a '[value, setter]' pair.",
                declarator.span(),
            );
            return;
        }
        let BindingPattern::ArrayPattern(array) = &declarator.id else {
            return;
        };
        if array.elements.len() != 2 || array.rest.is_some() {
            return;
        }
        let (Some(value), Some(setter)) = (&array.elements[0], &array.elements[1]) else {
            return;
        };
        let (Some(value), Some(setter)) = (
            binding_identifier_name(value),
            binding_identifier_name(setter),
        ) else {
            return;
        };
        if !is_state_setter_name(setter) || capitalize_first(value) != setter[3..] {
            self.sink.emit_span(
                RuleScope::Both,
                "S6754",
                "Rename this 'useState' pair to follow the '[value, setValue]' naming convention.",
                declarator.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6442_flags_plain_use_state_binding() {
        let findings = js_keys("const state = useState(0);\n");
        assert_eq!(count_key(&findings, "javascript:S6442"), 1);
    }

    #[test]
    fn s6442_allows_destructured_pair() {
        let findings = js_keys("const [value, setValue] = useState(0);\n");
        assert_eq!(count_key(&findings, "javascript:S6442"), 0);
    }

    #[test]
    fn s6754_flags_asymmetric_setter_name() {
        let findings = js_keys("const [count, setValue] = useState(0);\n");
        assert_eq!(count_key(&findings, "javascript:S6754"), 1);
    }

    #[test]
    fn s6754_allows_three_element_pattern() {
        let findings = js_keys("const [a, setA, other] = useState(0);\n");
        assert_eq!(count_key(&findings, "javascript:S6754"), 0);
    }
}
