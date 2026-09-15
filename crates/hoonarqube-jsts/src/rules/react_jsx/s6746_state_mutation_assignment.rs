use super::walker::ReactCollector;
use crate::rules::shared::{call_property, expression_through_this_link};

impl ReactCollector<'_> {
    /// Whether the current position sits in a React component: a class
    /// extending the built-in React bases, or a JSX-rendering component
    /// frame. Elsewhere, `this.state` is an ordinary field (`S6746`
    /// provenance gate).
    pub(crate) fn inside_react_component(&self) -> bool {
        self.react_class_depth > 0 || self.component_stack.last() == Some(&true)
    }
}
use crate::support::RuleScope;
use crate::support::member_object;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::SimpleAssignmentTarget;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6746` assignment half: writes into `this.state.*`.
    pub(crate) fn check_state_mutation_assignment(
        &mut self,
        assignment: &AssignmentExpression<'_>,
    ) {
        if !self.inside_react_component() {
            return;
        }
        let through_state = match assignment.left.as_simple_assignment_target() {
            Some(SimpleAssignmentTarget::StaticMemberExpression(member)) => {
                (matches!(&member.object, Expression::ThisExpression(_))
                    && member.property.name == "state")
                    || expression_through_this_state(&member.object)
            }
            Some(SimpleAssignmentTarget::ComputedMemberExpression(member)) => {
                expression_through_this_state(&member.object)
            }
            _ => false,
        };
        if through_state {
            self.sink.emit_span(
                RuleScope::Both,
                "S6746",
                "Update state immutably; mutate a copy instead of 'this.state'.",
                assignment.left.span(),
            );
        }
    }

    /// `S6746` call half: in-place mutations on `this.state.*` chains.
    pub(crate) fn check_state_mutation_call(&mut self, call: &CallExpression<'_>) {
        if !self.inside_react_component() {
            return;
        }
        let Some((property, member)) = call_property(call) else {
            return;
        };
        if STATE_MUTATION_METHODS.contains(&property)
            && expression_through_this_state(member_object(member))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6746",
                "Update state immutably; mutate a copy instead of 'this.state'.",
                call.span(),
            );
        }
    }
}

/// In-place array mutations flagged on `this.state` chains (`S6746`).
const STATE_MUTATION_METHODS: [&str; 9] = [
    "push",
    "pop",
    "shift",
    "unshift",
    "splice",
    "sort",
    "reverse",
    "fill",
    "copyWithin",
];

/// Whether a member chain passes through a `this.state` link (`S6746`).
fn expression_through_this_state(expression: &Expression<'_>) -> bool {
    expression_through_this_link(expression, "state")
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6746_flags_assignment_into_this_state() {
        let findings = js_keys(
            "class Widget extends Component {\n  update() {\n    this.state.count = 5;\n  }\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6746"), 1);
    }

    #[test]
    fn s6746_never_flags_non_react_state_fields() {
        // Issue #381: plain classes with a `state` data field are not React
        // components.
        let plain_class = js_keys(
            "class Worksheet {\n  constructor(options) {\n    this.state = options.state || 'visible';\n  }\n}\n",
        );
        assert_eq!(count_key(&plain_class, "javascript:S6746"), 0);
        let bare = js_keys("this.state.count = 5;\n");
        assert_eq!(count_key(&bare, "javascript:S6746"), 0);
    }

    #[test]
    fn s6746_flags_in_place_mutation_call_on_this_state() {
        let findings = js_keys(
            "class Widget extends Component {\n  update() {\n    this.state.items.push(1);\n  }\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6746"), 1);
    }

    #[test]
    fn s6746_allows_mutating_a_copy() {
        let findings = js_keys("const copy = [...this.state.items];\ncopy.push(1);\n");
        assert_eq!(count_key(&findings, "javascript:S6746"), 0);
    }

    #[test]
    fn s6746_ignores_this_props_chains() {
        let findings = js_keys("this.props.items.push(1);\n");
        assert_eq!(count_key(&findings, "javascript:S6746"), 0);
    }
}
