use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::AssignmentOperator;
use oxc_ast::ast::AwaitExpression;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Class;
use oxc_ast::ast::ClassElement;
use oxc_ast::ast::Expression;
use oxc_ast::ast::MethodDefinitionKind;
use oxc_ast::ast::PropertyKey;
use oxc_ast::ast::SimpleAssignmentTarget;
use oxc_span::{GetSpan, Span};

/// State needed by `S7059` while the shared batch traversal walks a file.
#[derive(Default)]
pub(crate) struct S7059State {
    function_depth: u32,
    constructor_function_depths: Vec<u32>,
    async_instance_methods: Vec<Vec<String>>,
    current_statement: Option<Span>,
    constructor_overrides: Vec<Vec<(String, bool)>>,
    reported_statements: Vec<Span>,
}

/// `S7059` helper: is the callee an async function/arrow expression?
fn callee_is_async_function(callee: &Expression<'_>) -> bool {
    match unparenthesized(callee) {
        Expression::ArrowFunctionExpression(arrow) => arrow.r#async,
        Expression::FunctionExpression(function) => function.r#async,
        _ => false,
    }
}

fn method_key_name<'a>(key: &PropertyKey<'a>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(identifier.name.as_str()),
        PropertyKey::StringLiteral(literal) => Some(literal.value.as_str()),
        PropertyKey::TemplateLiteral(template)
            if template.expressions.is_empty() && template.quasis.len() == 1 =>
        {
            let value = &template.quasis[0].value;
            value
                .cooked
                .as_ref()
                .map(oxc_ast::ast::Str::as_str)
                .or_else(|| Some(value.raw.as_str()))
        }
        _ => None,
    }
}
fn static_string_value<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    match unparenthesized(expression) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        Expression::TemplateLiteral(template)
            if template.expressions.is_empty() && template.quasis.len() == 1 =>
        {
            let value = &template.quasis[0].value;
            value
                .cooked
                .as_ref()
                .map(oxc_ast::ast::Str::as_str)
                .or_else(|| Some(value.raw.as_str()))
        }
        _ => None,
    }
}

fn record_instance_method(methods: &mut Vec<String>, name: &str, is_async: bool) {
    if let Some(index) = methods.iter().position(|method| method == name) {
        methods.remove(index);
    }
    if is_async {
        methods.push(name.to_owned());
    }
}

fn async_instance_method_names(class: &Class<'_>) -> Vec<String> {
    let mut methods = Vec::new();
    for element in &class.body.body {
        let ClassElement::MethodDefinition(method) = element else {
            continue;
        };
        if method.r#static {
            continue;
        }
        let Some(name) = method_key_name(&method.key) else {
            continue;
        };
        record_instance_method(
            &mut methods,
            name,
            method.kind == MethodDefinitionKind::Method && method.value.r#async,
        );
    }
    for element in &class.body.body {
        let ClassElement::PropertyDefinition(property) = element else {
            continue;
        };
        if property.r#static {
            continue;
        }
        let Some(name) = method_key_name(&property.key) else {
            continue;
        };
        record_instance_method(
            &mut methods,
            name,
            property
                .value
                .as_ref()
                .is_some_and(|value| callee_is_async_function(value)),
        );
    }
    methods
}

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    pub(crate) fn s7059_enter_class(&mut self, class: &Class<'_>) {
        self.s7059
            .async_instance_methods
            .push(async_instance_method_names(class));
    }

    pub(crate) fn s7059_leave_class(&mut self) {
        self.s7059.async_instance_methods.pop();
    }

    pub(crate) fn s7059_enter_function(&mut self, constructor: bool) {
        self.s7059.function_depth += 1;
        if constructor {
            self.s7059
                .constructor_function_depths
                .push(self.s7059.function_depth);
            self.s7059.constructor_overrides.push(Vec::new());
        }
    }

    pub(crate) fn s7059_leave_function(&mut self, constructor: bool) {
        if constructor {
            self.s7059.constructor_function_depths.pop();
            self.s7059.constructor_overrides.pop();
        }
        self.s7059.function_depth -= 1;
    }

    pub(crate) fn s7059_enter_statement(&mut self, span: Span) -> Option<Span> {
        let previous = self.s7059.current_statement;
        self.s7059.current_statement = Some(span);
        previous
    }

    pub(crate) fn s7059_leave_statement(&mut self, previous: Option<Span>) {
        self.s7059.current_statement = previous;
    }

    fn s7059_in_constructor_execution(&self) -> bool {
        self.constructor_depth > 0
            && self
                .s7059
                .constructor_function_depths
                .last()
                .is_some_and(|depth| *depth == self.s7059.function_depth)
    }

    fn s7059_async_instance_method_call(&self, callee: &Expression<'_>) -> bool {
        let (object, name) = match unparenthesized(callee) {
            Expression::StaticMemberExpression(member) => {
                (&member.object, Some(member.property.name.as_str()))
            }
            Expression::ComputedMemberExpression(member) => {
                (&member.object, static_string_value(&member.expression))
            }
            _ => return false,
        };
        let Some(name) = name else {
            return false;
        };
        if !matches!(unparenthesized(object), Expression::ThisExpression(_)) {
            return false;
        }
        if let Some(overrides) = self.s7059.constructor_overrides.last()
            && let Some((_, is_async)) = overrides.iter().rev().find(|(method, _)| method == name)
        {
            return *is_async;
        }
        self.s7059
            .async_instance_methods
            .last()
            .is_some_and(|methods| methods.iter().any(|method| method == name))
    }

    fn emit_s7059_once(&mut self, span: Span) {
        let report_span = self.s7059.current_statement.unwrap_or(span);
        if self.s7059.reported_statements.contains(&report_span) {
            return;
        }
        self.s7059.reported_statements.push(report_span);
        self.sink.emit_span(
            RuleScope::Both,
            "S7059",
            "Move this asynchronous work out of the constructor.",
            report_span,
        );
    }

    pub(crate) fn check_s7059_assignment_expression(&mut self, it: &AssignmentExpression<'_>) {
        if !self.s7059_in_constructor_execution() || it.operator != AssignmentOperator::Assign {
            return;
        }
        let Some(target) = it.left.as_simple_assignment_target() else {
            return;
        };
        let (object, name) = match target {
            SimpleAssignmentTarget::StaticMemberExpression(member) => {
                (&member.object, Some(member.property.name.as_str()))
            }
            SimpleAssignmentTarget::ComputedMemberExpression(member) => {
                (&member.object, static_string_value(&member.expression))
            }
            _ => return,
        };
        let Some(name) = name else {
            return;
        };
        if !matches!(unparenthesized(object), Expression::ThisExpression(_)) {
            return;
        }
        let async_value = callee_is_async_function(&it.right);
        let Some(overrides) = self.s7059.constructor_overrides.last_mut() else {
            return;
        };
        if let Some((_, previous)) = overrides.iter_mut().find(|(method, _)| method == name) {
            *previous = async_value;
        } else {
            overrides.push((name.to_owned(), async_value));
        }
    }

    /// `S7059` logic extracted from `visit_call_expression`.
    pub(crate) fn check_s7059_call_expression(&mut self, it: &CallExpression<'_>) {
        if self.s7059_in_constructor_execution()
            && (callee_is_async_function(&it.callee)
                || self.s7059_async_instance_method_call(&it.callee))
        {
            self.emit_s7059_once(it.span());
        }
    }

    /// `S7059` logic extracted from `visit_await_expression`.
    pub(crate) fn check_s7059_await_expression(&mut self, it: &AwaitExpression<'_>) {
        if self.s7059_in_constructor_execution() {
            self.emit_s7059_once(it.span());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{count_key, js_keys, ts_keys};

    #[test]
    fn deferred_async_callbacks_are_not_constructor_work() {
        let source =
            "class Example { constructor() { this.work = async () => { await work(); }; } }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7059"), 0);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7059"), 0);
    }

    #[test]
    fn called_async_instance_methods_are_constructor_work() {
        let source =
            "class Example { constructor() { this.work(); } async work() { await work(); } }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7059"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7059"), 1);
    }

    #[test]
    fn async_iife_and_inner_await_report_once() {
        let source = "class Example { constructor() { const pending = (async () => { await work(); })(); void pending; } }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7059"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7059"), 1);
    }
    #[test]
    fn this_calls_resolve_against_the_innermost_class() {
        let source = "class Outer { async work() {} constructor() { class Inner { work() {} constructor() { this.work(); } } } }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7059"), 0);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7059"), 0);
    }
    #[test]
    fn computed_async_instance_methods_are_resolved() {
        let source = "class Example { constructor() { this['work'](); } async ['work']() {} }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7059"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7059"), 1);
    }

    #[test]
    fn later_synchronous_method_overrides_async_method() {
        let source = "class Example { async work() {} work() {} constructor() { this.work(); } }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7059"), 0);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7059"), 0);
    }
    #[test]
    fn synchronous_instance_fields_and_assignments_shadow_async_methods() {
        let source = "class Example { work = () => {}; async work() {} constructor() { this.work = () => {}; this.work(); this['work'](); } }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7059"), 0);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7059"), 0);
    }

    #[test]
    fn async_instance_assignment_remains_constructor_work() {
        let source = "class Example { work = () => {}; constructor() { this.work = async () => {}; this.work(); } }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7059"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7059"), 1);
    }
}
