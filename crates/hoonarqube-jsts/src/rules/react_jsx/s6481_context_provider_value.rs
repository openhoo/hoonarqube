use super::walker::{ContextBinding, ReactCollector};
use crate::engine::scope_model::bound_names;
use crate::rules::shared::jsx_find_attribute;
use crate::support::{RuleScope, binding_identifier_name, unparenthesized};
use oxc_ast::ast::AssignmentTarget;
use oxc_ast::ast::AssignmentTargetMaybeDefault;
use oxc_ast::ast::AssignmentTargetProperty;
use oxc_ast::ast::Expression;
use oxc_ast::ast::FormalParameters;
use oxc_ast::ast::JSXAttributeValue;
use oxc_ast::ast::JSXElement;
use oxc_ast::ast::VariableDeclarator;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    pub(crate) fn push_context_binding(&mut self, name: &str, fresh: bool) {
        self.context_bindings.push(ContextBinding {
            name: name.to_string(),
            fresh,
        });
    }

    /// Records a local value whose identity is reconstructed on every render.
    /// The binding stack is scoped by the walker, so module-level constants
    /// and shadowed values remain distinct.
    pub(crate) fn record_context_binding(&mut self, declarator: &VariableDeclarator<'_>) {
        if self.component_stack.last() != Some(&true) {
            return;
        }
        let names = bound_names(&declarator.id);
        if names.is_empty() {
            return;
        }
        let fresh = names.len() == 1
            && binding_identifier_name(&declarator.id).is_some()
            && declarator.init.as_ref().is_some_and(|init| {
                matches!(
                    unparenthesized(init),
                    Expression::ObjectExpression(_)
                        | Expression::ArrayExpression(_)
                        | Expression::ArrowFunctionExpression(_)
                        | Expression::FunctionExpression(_)
                )
            });
        for name in names {
            self.push_context_binding(name, fresh);
        }
    }

    pub(crate) fn invalidate_context_binding(&mut self, name: &str) {
        if let Some(binding) = self
            .context_bindings
            .iter_mut()
            .rev()
            .find(|binding| binding.name == name)
        {
            binding.fresh = false;
        }
    }
    fn nearest_context_binding(&self, name: &str) -> Option<&ContextBinding> {
        self.context_bindings
            .iter()
            .rev()
            .find(|binding| binding.name == name)
    }

    pub(crate) fn invalidate_context_target(&mut self, target: &AssignmentTarget<'_>) {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                self.invalidate_context_binding(identifier.name.as_str());
            }
            AssignmentTarget::ArrayAssignmentTarget(array) => {
                for element in array.elements.iter().flatten() {
                    self.invalidate_context_target_maybe_default(element);
                }
                if let Some(rest) = &array.rest {
                    self.invalidate_context_target(&rest.target);
                }
            }
            AssignmentTarget::ObjectAssignmentTarget(object) => {
                for property in &object.properties {
                    match property {
                        AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(property) => {
                            self.invalidate_context_binding(property.binding.name.as_str());
                        }
                        AssignmentTargetProperty::AssignmentTargetPropertyProperty(property) => {
                            self.invalidate_context_target_maybe_default(&property.binding);
                        }
                    }
                }
                if let Some(rest) = &object.rest {
                    self.invalidate_context_target(&rest.target);
                }
            }
            _ => {}
        }
    }

    fn invalidate_context_target_maybe_default(
        &mut self,
        target: &AssignmentTargetMaybeDefault<'_>,
    ) {
        if let AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(target) = target {
            self.invalidate_context_target(&target.binding);
        } else if let Some(target) = target.as_assignment_target() {
            self.invalidate_context_target(target);
        }
    }

    fn context_binding_is_fresh(&self, expression: &Expression<'_>) -> bool {
        let Expression::Identifier(identifier) = unparenthesized(expression) else {
            return false;
        };
        self.component_stack.last() == Some(&true)
            && self
                .nearest_context_binding(identifier.name.as_str())
                .is_some_and(|binding| binding.fresh)
    }

    pub(crate) fn record_context_parameters(&mut self, parameters: &FormalParameters<'_>) {
        for parameter in &parameters.items {
            for name in bound_names(&parameter.pattern) {
                self.push_context_binding(name, false);
            }
        }
        if let Some(rest) = &parameters.rest {
            for name in bound_names(&rest.rest.argument) {
                self.push_context_binding(name, false);
            }
        }
    }

    /// `S6481`: freshly created object, array, or function values passed to
    /// `Context.Provider`, including simple local aliases.
    pub(crate) fn check_context_provider_value(&mut self, element: &JSXElement<'_>) {
        let oxc_ast::ast::JSXElementName::MemberExpression(member) = &element.opening_element.name
        else {
            return;
        };
        if member.property.name != "Provider" {
            return;
        }
        let Some(value_attribute) = jsx_find_attribute(&element.opening_element, "value") else {
            return;
        };
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &value_attribute.value else {
            return;
        };
        let Some(expression) = container.expression.as_expression() else {
            return;
        };
        let fresh = matches!(
            unparenthesized(expression),
            Expression::ObjectExpression(_)
                | Expression::ArrayExpression(_)
                | Expression::ArrowFunctionExpression(_)
                | Expression::FunctionExpression(_)
        ) || self.context_binding_is_fresh(expression);
        if fresh {
            self.sink.emit_span(
                RuleScope::Both,
                "S6481",
                "The object passed as the value prop to the Context provider changes every render. To fix this consider wrapping it in a useMemo hook.",
                expression.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6481_flags_inline_object_provider_value() {
        let findings = jsx_keys("const el = <Ctx.Provider value={{a: 1}}></Ctx.Provider>;\n");
        assert_eq!(count_key(&findings, "javascript:S6481"), 1);
    }

    #[test]
    fn s6481_flags_inline_array_provider_value() {
        let findings = jsx_keys("const el = <Ctx.Provider value={[]}></Ctx.Provider>;\n");
        assert_eq!(count_key(&findings, "javascript:S6481"), 1);
    }

    #[test]
    fn s6481_allows_memoized_provider_value() {
        let findings = jsx_keys("const el = <Ctx.Provider value={memo}></Ctx.Provider>;\n");
        assert_eq!(count_key(&findings, "javascript:S6481"), 0);
    }

    #[test]
    fn s6481_ignores_non_provider_member_elements() {
        let findings = jsx_keys("const el = <Ctx.Consumer value={{a: 1}}></Ctx.Consumer>;\n");
        assert_eq!(count_key(&findings, "javascript:S6481"), 0);
    }

    #[test]
    fn s6481_allows_hoisted_module_level_memo_const() {
        // Stable module-level references remain clean.
        let findings = jsx_keys(
            "const memo = {a: 1};\nconst el = <Ctx.Provider value={memo}></Ctx.Provider>;\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6481"), 0);
    }

    #[test]
    fn s6481_flags_fresh_local_aliases_but_not_memoized_values() {
        let findings = jsx_keys(
            "function Panel() {\n  const value = {ready: true};\n  return <Ctx.Provider value={value}>ok</Ctx.Provider>;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6481"), 1);

        let memoized = jsx_keys(
            "function Panel() {\n  const value = useMemo(() => ({ready: true}), []);\n  return <Ctx.Provider value={value}>ok</Ctx.Provider>;\n}\n",
        );
        assert_eq!(count_key(&memoized, "javascript:S6481"), 0);
    }

    #[test]
    fn s6481_restores_outer_binding_after_shadowing_block() {
        let findings = jsx_keys(
            "function Panel() {\n  const value = {ready: true};\n  {\n    const value = stable;\n    void value;\n  }\n  return <Ctx.Provider value={value}>ok</Ctx.Provider>;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6481"), 1);
    }

    #[test]
    fn s6481_shadows_fresh_alias_for_destructuring_callback_and_catch_bindings() {
        let destructured = jsx_keys(
            "function Panel() {\n  const value = {ready: true};\n  {\n    const {value} = source;\n    return <Ctx.Provider value={value}/>;\n  }\n}\n",
        );

        assert_eq!(count_key(&destructured, "javascript:S6481"), 0);

        let callback = jsx_keys(
            "function Panel() {\n  const value = {ready: true};\n  return rows.map(value => <Ctx.Provider value={value}/>);\n}\n",
        );
        assert_eq!(count_key(&callback, "javascript:S6481"), 0);

        let caught = jsx_keys(
            "function Panel() {\n  const value = {ready: true};\n  try { throw stable; } catch (value) {\n    return <Ctx.Provider value={value}/>;\n  }\n}\n",
        );
        assert_eq!(count_key(&caught, "javascript:S6481"), 0);
    }
    #[test]
    fn s6481_drops_freshness_after_alias_reassignment() {
        let findings = jsx_keys(
            "const stable = {};\nfunction Panel() {\n  let value = {};\n  value = stable;\n  return <Ctx.Provider value={value}/>;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6481"), 0);
    }

    #[test]
    fn s6481_flags_fresh_function_aliases_and_declarations() {
        let alias = jsx_keys(
            "function Panel() {\n  const value = () => 1;\n  return <Ctx.Provider value={value}/>;\n}\n",
        );
        assert_eq!(count_key(&alias, "javascript:S6481"), 1);

        let declaration = jsx_keys(
            "function Panel() {\n  function value() { return 1; }\n  return <Ctx.Provider value={value}/>;\n}\n",
        );
        assert_eq!(count_key(&declaration, "javascript:S6481"), 1);
    }

    #[test]
    fn s6481_invalidates_destructuring_and_update_writes() {
        let update = jsx_keys(
            "function Panel() {\n  let value = {};\n  value++;\n  return <Ctx.Provider value={value}/>;\n}\n",
        );
        assert_eq!(count_key(&update, "javascript:S6481"), 0);

        let destructured = jsx_keys(
            "function Panel() {\n  let value = {};\n  ({value} = stable);\n  return <Ctx.Provider value={value}/>;\n}\n",
        );
        assert_eq!(count_key(&destructured, "javascript:S6481"), 0);
    }

    #[test]
    fn s6481_restores_outer_freshness_after_deferred_nested_reset() {
        let findings = jsx_keys(
            "const stable = {};\nfunction Panel() {\n  let value = {};\n  const helper = () => { value = stable; };\n  return <Ctx.Provider value={value}/>;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6481"), 1);
    }
}
