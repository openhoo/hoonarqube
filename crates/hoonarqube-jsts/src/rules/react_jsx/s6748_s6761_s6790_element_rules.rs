use super::walker::{ReactCollector, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::JSXAttributeValue;
use oxc_ast::ast::JSXElement;
use oxc_ast::ast::SimpleAssignmentTarget;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6748`, `S6761`, and the attribute half of `S6790`: conflicts
    /// between the `children` prop, `dangerouslySetInnerHTML`, and nested
    /// children, plus string `ref` attributes.
    pub(crate) fn check_element_rules(&mut self, element: &JSXElement<'_>) {
        let opening = &element.opening_element;
        let children_attribute = jsx_find_attribute(opening, "children");
        let raw_html_attribute = jsx_find_attribute(opening, "dangerouslySetInnerHTML");
        if let Some(attribute) = children_attribute
            && !element.children.is_empty()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6748",
                "Remove this 'children' prop; the component already receives nested children.",
                attribute.span(),
            );
        }
        if let (Some(_children), Some(raw_html)) = (children_attribute, raw_html_attribute) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6761",
                "Remove 'dangerouslySetInnerHTML' or the 'children' prop; using both together is redundant.",
                raw_html.span(),
            );
        }
        if let Some(attribute) = jsx_find_attribute(opening, "ref")
            && matches!(attribute.value, Some(JSXAttributeValue::StringLiteral(_)))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6790",
                "Replace this string ref with a callback ref.",
                attribute.span(),
            );
        }
    }

    /// `S6790` read half: any member chain rooted at `this.refs`.
    pub(crate) fn check_refs_access(&mut self, expression: &Expression<'_>) {
        let Expression::StaticMemberExpression(member) = expression else {
            return;
        };
        if !matches!(&member.object, Expression::ThisExpression(_))
            || member.property.name != "refs"
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6790",
            "Replace 'this.refs' accesses with callback refs.",
            member.span(),
        );
    }

    /// `S6790` write half: assignments into `this.refs.*`.
    pub(crate) fn check_refs_write(&mut self, assignment: &AssignmentExpression<'_>) {
        let Some(SimpleAssignmentTarget::StaticMemberExpression(member)) =
            assignment.left.as_simple_assignment_target()
        else {
            return;
        };
        if !matches!(&member.object, Expression::ThisExpression(_))
            || member.property.name != "refs"
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6790",
            "Replace 'this.refs' accesses with callback refs.",
            member.span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6748_flags_children_prop_with_nested_children() {
        let findings = jsx_keys("const el = <div children={x}>text</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6748"), 1);
    }

    #[test]
    fn s6748_allows_children_prop_without_nested_children() {
        let findings = jsx_keys("const el = <div children={x}></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6748"), 0);
    }

    #[test]
    fn s6761_flags_children_with_dangerously_set_inner_html() {
        let findings = jsx_keys(
            "const el = <div children={x} dangerouslySetInnerHTML={{__html: 'y'}}></div>;\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6761"), 1);
    }

    #[test]
    fn s6761_allows_raw_html_without_children_prop() {
        let findings =
            jsx_keys("const el = <div dangerouslySetInnerHTML={{__html: 'y'}}></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6761"), 0);
    }

    #[test]
    fn s6790_flags_string_ref_attribute() {
        let findings = jsx_keys("const el = <input ref=\"name\"></input>;\n");
        assert_eq!(count_key(&findings, "javascript:S6790"), 1);
    }

    #[test]
    fn s6790_allows_callback_ref_and_flags_this_refs_read() {
        let callback = jsx_keys("const el = <input ref={(node) => save(node)}></input>;\n");
        assert_eq!(count_key(&callback, "javascript:S6790"), 0);
        let refs_read = js_keys("this.refs.name.focus();\n");
        assert_eq!(count_key(&refs_read, "javascript:S6790"), 1);
    }
}
