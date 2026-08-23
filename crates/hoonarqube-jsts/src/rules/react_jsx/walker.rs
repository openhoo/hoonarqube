// Family walker for 'react_jsx' (generated).
use crate::context::{AnalysisContext, RuleOptions};
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::expression::walker::call_property;
use crate::support::{
    IssueSink, LineIndex, RuleScope, binding_identifier_name, callee_name, identifier_name,
    member_object, member_root_name, span_text_contains,
};
use crate::{JstsLanguage, REACT_DOM_ATTRIBUTES, expression_returns_jsx};
use hoonarqube_ir::Issue;
use oxc_allocator::ArenaVec;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentOperator, BindingPattern, CallExpression, Class, ClassElement,
    DoWhileStatement, Expression, ExpressionStatement, ForInStatement, ForOfStatement,
    ForStatement, FunctionBody, IfStatement, ImportDeclaration, ImportDeclarationSpecifier,
    JSXAttribute, JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement,
    JSXElementName, JSXExpression, JSXExpressionContainer, JSXFragment, JSXOpeningElement, JSXText,
    LogicalOperator, MethodDefinition, MethodDefinitionKind, ModuleExportName, ObjectPropertyKind,
    PropertyDefinition, PropertyKey, ReturnStatement, SimpleAssignmentTarget, Statement,
    VariableDeclarator, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_assignment_expression, walk_call_expression, walk_class, walk_do_while_statement,
    walk_expression, walk_expression_statement, walk_for_in_statement, walk_for_of_statement,
    walk_for_statement, walk_if_statement, walk_import_declaration, walk_jsx_children,
    walk_jsx_element, walk_jsx_expression_container, walk_jsx_fragment, walk_jsx_text,
    walk_method_definition, walk_property_definition, walk_statement, walk_this_expression,
    walk_variable_declarator, walk_while_statement,
};
use oxc_span::{GetSpan, Span};
use std::collections::BTreeMap;

/// All Batch4 React/JSX structural checks in one traversal (groups R1-R3):
/// `S6748`, `S6761`, `S6749`, `S6750`, `S6754`, `S6443`, `S6788`, `S6789`,
/// `S6790`, `S6791`, `S6957`, `S6763`, `S6746`, `S6766`, `S6438`, `S6480`,
/// `S6477`, `S6479`, `S6770`, `S6435`, `S6439`, `S6440`, `S6442`, `S6481`,
/// `S6478`, `S6756`, `S6757`, `S6772`, `S6774`, `S6775`, and `S6747`.
pub(crate) fn check_react_jsx_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut collector = ReactCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        rules,
        expression_statement_depth: 0,
        jsx_child_depth: 0,
        conditional_depth: 0,
        map_frames: Vec::new(),
        component_stack: Vec::new(),
        class_depth: 0,
        method_guard: 0,
        prop_declarations: BTreeMap::new(),
        prop_defaults: BTreeMap::new(),
    };
    collector.visit_program(program);
    collector.report_uncovered_defaults();
    collector.sink.issues
}

/// React/JSX structural rules in one traversal. Context stacks track
/// expression statements (`S6750`), `.map()` callbacks (`S6477`/`S6479`),
/// component nesting (`S6478`/`S6757`), and conditional/hook positions
/// (`S6440`); `source` backs the comment probe of `S6438`. The prop maps
/// feed the `S6775` post-pass.
pub(crate) struct ReactCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) source: &'index str,
    pub(crate) rules: &'index RuleOptions,
    pub(crate) expression_statement_depth: usize,
    pub(crate) jsx_child_depth: usize,
    pub(crate) conditional_depth: usize,
    pub(crate) map_frames: Vec<MapFrame>,
    pub(crate) component_stack: Vec<bool>,
    pub(crate) class_depth: usize,
    pub(crate) method_guard: usize,
    pub(crate) prop_declarations: BTreeMap<String, BTreeMap<String, PropKind>>,
    pub(crate) prop_defaults: BTreeMap<String, BTreeMap<String, Span>>,
}

impl<'a> Visit<'a> for ReactCollector<'_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'_>) {
        self.expression_statement_depth += 1;
        walk_expression_statement(self, it);
        self.expression_statement_depth -= 1;
    }

    fn visit_jsx_element(&mut self, it: &JSXElement<'_>) {
        self.check_map_root_key(it);
        self.check_element_rules(it);
        self.check_inline_function_values(it);
        self.check_index_key(it);
        self.check_unknown_tag(it);
        self.check_context_provider_value(it);
        self.check_unknown_attributes(it);
        walk_jsx_element(self, it);
    }

    fn visit_jsx_fragment(&mut self, it: &JSXFragment<'_>) {
        self.check_single_child_fragment(it);
        walk_jsx_fragment(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'_>) {
        self.check_react_dom_calls(it);
        self.check_noop_state_setter(it);
        self.check_state_mutation_call(it);
        self.check_set_state_argument(it);
        self.check_hook_call_site(it);
        let pushed_map_frame = match map_callback_frame(it) {
            Some(frame) => {
                self.map_frames.push(frame);
                true
            }
            None => false,
        };
        let argument_functions = call_argument_function_count(it);
        self.conditional_depth += argument_functions;
        walk_call_expression(self, it);
        self.conditional_depth -= argument_functions;
        if pushed_map_frame {
            self.map_frames.pop();
        }
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'_>) {
        self.check_use_state_pair(it);
        let frame = declarator_component_frame(it);
        if let Some((returns_jsx, name_span)) = frame {
            self.check_nested_component(returns_jsx, Some(name_span), it.span());
            self.component_stack.push(returns_jsx);
        }
        walk_variable_declarator(self, it);
        if frame.is_some() {
            self.component_stack.pop();
        }
    }

    fn visit_expression(&mut self, it: &Expression<'_>) {
        self.check_refs_access(it);
        walk_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'_>) {
        self.check_refs_write(it);
        self.check_state_mutation_assignment(it);
        self.collect_prop_metadata(it);
        walk_assignment_expression(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'_>) {
        self.method_guard += 1;
        self.check_legacy_lifecycle(it);
        walk_method_definition(self, it);
        self.method_guard -= 1;
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'_>) {
        self.method_guard += 1;
        walk_property_definition(self, it);
        self.method_guard -= 1;
    }

    fn visit_class(&mut self, it: &Class<'_>) {
        self.check_pure_component_update(it);
        self.check_render_method_return(it);
        self.check_props_without_prop_types(it);
        let is_component = class_returns_jsx(it);
        self.check_nested_component(is_component, it.id.as_ref().map(GetSpan::span), it.span());
        self.component_stack.push(is_component);
        self.class_depth += 1;
        walk_class(self, it);
        self.class_depth -= 1;
        self.component_stack.pop();
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'_>) {
        self.check_deprecated_import(it);
        walk_import_declaration(self, it);
    }

    fn visit_statement(&mut self, it: &Statement<'_>) {
        if let Statement::FunctionDeclaration(function) = it {
            let returns_jsx = function
                .body
                .as_ref()
                .is_some_and(|body| body_returns_jsx(body));
            self.check_nested_component(
                returns_jsx,
                function.id.as_ref().map(GetSpan::span),
                function.span(),
            );
            self.component_stack.push(returns_jsx);
        }
        walk_statement(self, it);
        if let Statement::FunctionDeclaration(_) = it {
            self.component_stack.pop();
        }
    }
    fn visit_this_expression(&mut self, it: &oxc_ast::ast::ThisExpression) {
        if self.method_guard == 0
            && self.class_depth == 0
            && self.component_stack.last() == Some(&true)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6757",
                "'this' is undefined inside a functional component; capture the needed values instead.",
                it.span(),
            );
        }
        walk_this_expression(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'_>) {
        self.conditional_depth += 1;
        walk_if_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'_>) {
        self.conditional_depth += 1;
        walk_for_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'_>) {
        self.conditional_depth += 1;
        walk_for_in_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'_>) {
        self.conditional_depth += 1;
        walk_for_of_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'_>) {
        self.conditional_depth += 1;
        walk_while_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'_>) {
        self.conditional_depth += 1;
        walk_do_while_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_jsx_text(&mut self, it: &JSXText<'_>) {
        self.check_unescaped_entities(it);
        walk_jsx_text(self, it);
    }

    fn visit_jsx_expression_container(&mut self, it: &JSXExpressionContainer<'_>) {
        self.check_empty_container(it);
        self.check_literal_conditional_child(it);
        walk_jsx_expression_container(self, it);
    }

    fn visit_jsx_children(&mut self, it: &ArenaVec<'a, JSXChild<'a>>) {
        self.jsx_child_depth += 1;
        self.check_whitespace_only_gaps(it);
        walk_jsx_children(self, it);
        self.jsx_child_depth -= 1;
    }
}

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

    pub(crate) fn check_single_child_fragment(&mut self, fragment: &JSXFragment<'_>) {
        let single_child = matches!(
            fragment.children.as_slice(),
            [JSXChild::Element(_) | JSXChild::ExpressionContainer(_)]
        );
        if single_child {
            self.sink.emit_span(
                RuleScope::Both,
                "S6749",
                "Remove this unnecessary fragment; it wraps a single child.",
                fragment.span(),
            );
        }
    }

    /// `S6750`, `S6788`, `S6789`, and the call half of `S6957`: deprecated
    /// `ReactDOM` entry points and `this.isMounted` probes.
    pub(crate) fn check_react_dom_calls(&mut self, call: &CallExpression<'_>) {
        if let Some((property, member)) = call_property(call) {
            let root = member_root_name(member);
            let is_render = root == Some("ReactDOM") && property == "render";
            let is_find_dom_node = root == Some("ReactDOM") && property == "findDOMNode";
            let is_create_class =
                (root == Some("React") || root == Some("ReactDOM")) && property == "createClass";
            if is_render && self.expression_statement_depth == 0 {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6750",
                    "'ReactDOM.render' should be called as a statement; do not consume its return value.",
                    call.span(),
                );
            }
            if is_find_dom_node {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6788",
                    "'ReactDOM.findDOMNode' is deprecated; use refs instead.",
                    call.span(),
                );
            }
            if is_render || is_find_dom_node || is_create_class {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6957",
                    "Remove this deprecated React API usage.",
                    call.span(),
                );
            }
        }
        if callee_this_property(call) == Some("isMounted") {
            self.sink.emit_span(
                RuleScope::Both,
                "S6789",
                "'this.isMounted' is deprecated and unreliable; track mounted state explicitly.",
                call.callee.span(),
            );
        }
    }

    /// `S6443`: `setX(x)` calls passing the state variable back to its own
    /// setter.
    pub(crate) fn check_noop_state_setter(&mut self, call: &CallExpression<'_>) {
        let Some(callee) = callee_name(call) else {
            return;
        };
        if !is_state_setter_name(callee) || call.arguments.len() != 1 {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Some(name) = identifier_name(argument) else {
            return;
        };
        if capitalize_first(name) == callee[3..] {
            self.sink.emit_span(
                RuleScope::Both,
                "S6443",
                "Pass a different value or an updater function; setting the state to itself changes nothing.",
                call.span(),
            );
        }
    }

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

    /// `S6791`: legacy lifecycle method names on class bodies.
    pub(crate) fn check_legacy_lifecycle(&mut self, method: &MethodDefinition<'_>) {
        if method.kind == MethodDefinitionKind::Constructor {
            return;
        }
        let Some(name) = duplicated_key_name(&method.key) else {
            return;
        };
        if LEGACY_LIFECYCLE_METHODS.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6791",
                "This legacy lifecycle method is deprecated; use the 'UNSAFE_'-prefixed version or refactor.",
                method.key.span(),
            );
        }
    }
    /// `S6957` import half: `prop-types` sources and `PropTypes` names.
    pub(crate) fn check_deprecated_import(&mut self, declaration: &ImportDeclaration<'_>) {
        let prop_types_import = declaration.source.value == "prop-types"
            || declaration
                .specifiers
                .iter()
                .flatten()
                .any(|specifier| match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(imported) => {
                        module_export_name_is(&imported.imported, "PropTypes")
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(defaulted) => {
                        defaulted.local.name == "PropTypes"
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => false,
                });
        if prop_types_import {
            self.sink.emit_span(
                RuleScope::Both,
                "S6957",
                "Remove this deprecated React API usage; PropTypes checks vanish in production builds.",
                declaration.span(),
            );
        }
    }

    /// `S6763`: `shouldComponentUpdate` is pointless on `PureComponent`.
    pub(crate) fn check_pure_component_update(&mut self, class: &Class<'_>) {
        let Some(heritage) = &class.heritage else {
            return;
        };
        let pure_base = match &heritage.expression {
            Expression::Identifier(identifier) => identifier.name.ends_with("PureComponent"),
            Expression::StaticMemberExpression(member) => member.property.name == "PureComponent",
            _ => false,
        };
        if !pure_base {
            return;
        }
        for element in &class.body.body {
            let ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if duplicated_key_name(&method.key) != Some("shouldComponentUpdate") {
                continue;
            }
            self.sink.emit_span(
                RuleScope::Both,
                "S6763",
                "'shouldComponentUpdate' is useless on a PureComponent subclass; remove it.",
                method.key.span(),
            );
        }
    }

    /// `S6435`: class `render` methods must return JSX or null somewhere.
    pub(crate) fn check_render_method_return(&mut self, class: &Class<'_>) {
        for element in &class.body.body {
            let ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if duplicated_key_name(&method.key) != Some("render")
                || method.kind != MethodDefinitionKind::Method
            {
                continue;
            }
            let Some(body) = &method.value.body else {
                continue;
            };
            let mut scanner = RenderReturnScanner::default();
            scanner.visit_function_body(body);
            if !scanner.satisfied {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6435",
                    "Add a return statement returning JSX or null to this 'render' method.",
                    method.key.span(),
                );
            }
        }
    }

    /// `S6746` assignment half: writes into `this.state.*`.
    pub(crate) fn check_state_mutation_assignment(
        &mut self,
        assignment: &AssignmentExpression<'_>,
    ) {
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

    /// `S6438`: empty expression containers whose comment content was
    /// dropped by the lexer.
    pub(crate) fn check_empty_container(&mut self, container: &JSXExpressionContainer<'_>) {
        if !matches!(&container.expression, JSXExpression::EmptyExpression(_)) {
            return;
        }
        let span = container.span();
        if span_text_contains(self.source, span, "/*")
            || span_text_contains(self.source, span, "//")
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6438",
            "Remove this empty JSX expression container.",
            span,
        );
    }

    /// `S6439`: `{literal && <element/>}` children render the literal when
    /// the condition is falsy-but-present.
    pub(crate) fn check_literal_conditional_child(
        &mut self,
        container: &JSXExpressionContainer<'_>,
    ) {
        if self.jsx_child_depth == 0 {
            return;
        }
        let Some(Expression::LogicalExpression(logical)) = container.expression.as_expression()
        else {
            return;
        };
        if logical.operator != LogicalOperator::And
            || !matches!(
                logical.left,
                Expression::NumericLiteral(_)
                    | Expression::StringLiteral(_)
                    | Expression::BigIntLiteral(_)
            )
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6439",
            "This branch renders a literal; guard it with an explicit boolean condition.",
            container.span(),
        );
    }

    /// `S6480`: inline arrow or `.bind(...)` attribute values create a new
    /// function on every render.
    pub(crate) fn check_inline_function_values(&mut self, element: &JSXElement<'_>) {
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(JSXAttributeValue::ExpressionContainer(container)) = &attribute.value else {
                continue;
            };
            let inline = match container.expression.as_expression() {
                Some(Expression::ArrowFunctionExpression(_)) => true,
                Some(Expression::CallExpression(call)) => matches!(
                    &call.callee,
                    Expression::StaticMemberExpression(member) if member.property.name == "bind"
                ),
                _ => false,
            };
            if inline {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6480",
                    "Create this function outside of the render path; a fresh instance is created on every render.",
                    attribute.span(),
                );
            }
        }
    }

    /// `S6479`: `key={index}` where `index` is the surrounding `.map()`
    /// callback's second parameter.
    pub(crate) fn check_index_key(&mut self, element: &JSXElement<'_>) {
        let Some(index_param) = self
            .map_frames
            .last()
            .and_then(|frame| frame.index_param.clone())
        else {
            return;
        };
        let Some(key_attribute) = jsx_find_attribute(&element.opening_element, "key") else {
            return;
        };
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &key_attribute.value else {
            return;
        };
        let is_index_key = matches!(
            container.expression.as_expression(),
            Some(Expression::Identifier(reference)) if reference.name == index_param.as_str()
        );
        if is_index_key {
            self.sink.emit_span(
                RuleScope::Both,
                "S6479",
                "Avoid using the array index as the 'key'; use a stable identifier instead.",
                key_attribute.span(),
            );
        }
    }

    /// `S6770`: lowercase tag names that are neither DOM elements nor
    /// custom elements.
    pub(crate) fn check_unknown_tag(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if jsx_tag_is_intrinsic(tag) && !tag.contains('-') && !HTML_TAG_ALLOWLIST.contains(&tag) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6770",
                "Capitalize this component name; lowercase tags are treated as built-in DOM elements.",
                element.opening_element.name.span(),
            );
        }
    }

    /// `S6477`: root elements returned from `.map()` callbacks need keys.
    pub(crate) fn check_map_root_key(&mut self, element: &JSXElement<'_>) {
        let needs_key = match self.map_frames.last_mut() {
            Some(frame) if !frame.root_checked => {
                frame.root_checked = true;
                frame.index_param.is_some()
            }
            _ => return,
        };
        if !needs_key
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "key").is_some()
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6477",
            "Add a 'key' prop to this element returned from '.map()'.",
            element.opening_element.span(),
        );
    }
    /// `S6440`: hook calls under conditions, loops, or callbacks.
    pub(crate) fn check_hook_call_site(&mut self, call: &CallExpression<'_>) {
        if self.conditional_depth == 0 {
            return;
        }
        let Some(callee) = callee_name(call) else {
            return;
        };
        let Some(tail) = callee.strip_prefix("use") else {
            return;
        };
        if !tail.starts_with(|ch: char| ch.is_ascii_uppercase()) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6440",
            "Move this hook call to the top level of the component; hooks must not run conditionally.",
            call.span(),
        );
    }

    /// `S6756`: `this.setState` arguments reaching into `this.state`
    /// instead of using the updater form.
    pub(crate) fn check_set_state_argument(&mut self, call: &CallExpression<'_>) {
        let is_method_call = matches!(
            &call.callee,
            Expression::StaticMemberExpression(member)
                if member.property.name == "setState"
                    && matches!(&member.object, Expression::ThisExpression(_))
        );
        if !is_method_call {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let mut scanner = ThisStateReferenceScanner::default();
        scanner.visit_expression(argument);
        if scanner.found {
            self.sink.emit_span(
                RuleScope::Both,
                "S6756",
                "Use the updater form of 'setState'; reading 'this.state' during the update misses batching.",
                call.span(),
            );
        }
    }

    /// `S6481`: inline objects or arrays passed as `Context.Provider`
    /// values.
    pub(crate) fn check_context_provider_value(&mut self, element: &JSXElement<'_>) {
        let JSXElementName::MemberExpression(member) = &element.opening_element.name else {
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
        if matches!(
            container.expression.as_expression(),
            Some(Expression::ObjectExpression(_) | Expression::ArrayExpression(_))
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6481",
                "Pass a memoized 'value' instead of a fresh object or array literal.",
                value_attribute.span(),
            );
        }
    }

    /// `S6478`: components defined inside other components.
    pub(crate) fn check_nested_component(
        &mut self,
        returns_jsx: bool,
        name_span: Option<Span>,
        fallback_span: Span,
    ) {
        if !returns_jsx
            || !self.component_stack.iter().any(|&component| component)
            || self.method_guard > 0
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6478",
            "Define this component outside of its parent component.",
            name_span.unwrap_or(fallback_span),
        );
    }

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

    /// `S6774`: class components touching `this.props` without declared
    /// `propTypes` (JavaScript files only).
    pub(crate) fn check_props_without_prop_types(&mut self, class: &Class<'_>) {
        let declares_prop_types = class.body.body.iter().any(|element| {
            let ClassElement::PropertyDefinition(definition) = element else {
                return false;
            };
            definition.r#static && duplicated_key_name(&definition.key) == Some("propTypes")
        });
        if declares_prop_types {
            return;
        }
        let mut scanner = ThisPropsScanner::default();
        scanner.visit_class(class);
        if scanner.found {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S6774",
                "Declare 'propTypes' for this class component or migrate its props to types.",
                class.span(),
            );
        }
    }

    /// `S6747`: unknown attributes on intrinsic elements.
    pub(crate) fn check_unknown_attributes(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            if attribute_is_known(name, &self.rules.jsx_attribute_whitelist) {
                continue;
            }
            let message = format!("'{name}' is not a known DOM or React attribute.");
            self.sink
                .emit_span(RuleScope::Both, "S6747", &message, attribute.span());
        }
    }

    /// `S6775` collection: records `X.propTypes` / `X.defaultProps`
    /// object assignments for the post-pass.
    pub(crate) fn collect_prop_metadata(&mut self, assignment: &AssignmentExpression<'_>) {
        if assignment.operator != AssignmentOperator::Assign {
            return;
        }
        let Some(SimpleAssignmentTarget::StaticMemberExpression(target)) =
            assignment.left.as_simple_assignment_target()
        else {
            return;
        };
        let Expression::ObjectExpression(object) = &assignment.right else {
            return;
        };
        let Some(component) = identifier_name(&target.object) else {
            return;
        };
        let kind = match target.property.name.as_str() {
            "propTypes" => PropSide::Declaration,
            "defaultProps" => PropSide::Default,
            _ => return,
        };
        for property_kind in &object.properties {
            let ObjectPropertyKind::ObjectProperty(property) = property_kind else {
                continue;
            };
            let Some(key) = duplicated_key_name(&property.key) else {
                continue;
            };
            match kind {
                PropSide::Declaration => {
                    let required = member_chain_has_link(&property.value, "isRequired");
                    let value = if required {
                        PropKind::Required
                    } else {
                        PropKind::Optional
                    };
                    self.prop_declarations
                        .entry(component.to_string())
                        .or_default()
                        .insert(key.to_string(), value);
                }
                PropSide::Default => {
                    self.prop_defaults
                        .entry(component.to_string())
                        .or_default()
                        .insert(key.to_string(), property.value.span());
                }
            }
        }
    }

    /// `S6775` post-pass: flags `defaultProps` entries without a matching
    /// `isRequired` declaration.
    pub(crate) fn report_uncovered_defaults(&mut self) {
        let mut uncovered = Vec::new();
        for (component, defaults) in &self.prop_defaults {
            let Some(declarations) = self.prop_declarations.get(component) else {
                continue;
            };
            for (property, span) in defaults {
                if declarations.get(property) != Some(&PropKind::Required) {
                    uncovered.push(*span);
                }
            }
        }
        for span in uncovered {
            self.sink.emit_span(
                RuleScope::Both,
                "S6775",
                "'defaultProps' entry without an 'isRequired' 'propTypes' declaration hides missing-prop mistakes.",
                span,
            );
        }
    }
}

/// Which side of the prop-metadata cross-check an assignment feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PropSide {
    Declaration,
    Default,
}

/// Subtree probe for reads through `this.props` (`S6774`).
#[derive(Default)]
pub(crate) struct ThisPropsScanner {
    pub(crate) found: bool,
}

impl Visit<'_> for ThisPropsScanner {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if expression_through_this_link(it, "props") {
            self.found = true;
            return;
        }
        walk_expression(self, it);
    }
}

/// Tags whose adjacent collapsible whitespace behaves inconsistently
/// (`S6772`).
pub(crate) const INLINE_TAGS: [&str; 36] = [
    "a", "abbr", "b", "bdi", "bdo", "br", "button", "cite", "code", "data", "dfn", "em", "i",
    "img", "input", "kbd", "label", "mark", "q", "rp", "rt", "ruby", "s", "samp", "select", "slot",
    "small", "span", "strong", "sub", "sup", "time", "u", "textarea", "var", "wbr",
];

/// Subtree probe for reads through `this.state` (`S6756`).
#[derive(Default)]
pub(crate) struct ThisStateReferenceScanner {
    pub(crate) found: bool,
}

impl Visit<'_> for ThisStateReferenceScanner {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if expression_through_this_link(it, "state") {
            self.found = true;
            return;
        }
        walk_expression(self, it);
    }
}

/// Known intrinsic tag names (`S6770`): HTML plus a common SVG surface.
pub(crate) const HTML_TAG_ALLOWLIST: &[&str] = &[
    "a",
    "abbr",
    "acronym",
    "address",
    "animate",
    "animateMotion",
    "animateTransform",
    "applet",
    "area",
    "article",
    "aside",
    "audio",
    "b",
    "base",
    "basefont",
    "bdi",
    "bdo",
    "big",
    "blockquote",
    "body",
    "br",
    "button",
    "canvas",
    "caption",
    "circle",
    "cite",
    "clipPath",
    "code",
    "col",
    "colgroup",
    "data",
    "datalist",
    "dd",
    "defs",
    "del",
    "desc",
    "details",
    "dfn",
    "dialog",
    "dir",
    "div",
    "dl",
    "dt",
    "ellipse",
    "em",
    "embed",
    "feBlend",
    "feColorMatrix",
    "feComponentTransfer",
    "feComposite",
    "feConvolveMatrix",
    "feDiffuseLighting",
    "feDisplacementMap",
    "feDistantLight",
    "feDropShadow",
    "feFlood",
    "feFuncA",
    "feFuncB",
    "feFuncG",
    "feFuncR",
    "feGaussianBlur",
    "feImage",
    "feMerge",
    "feMergeNode",
    "feMorphology",
    "feOffset",
    "fePointLight",
    "feSpecularLighting",
    "feSpotLight",
    "feTile",
    "feTurbulence",
    "fieldset",
    "figcaption",
    "figure",
    "filter",
    "font",
    "footer",
    "foreignObject",
    "form",
    "frame",
    "frameset",
    "g",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "head",
    "header",
    "hgroup",
    "hr",
    "html",
    "i",
    "iframe",
    "image",
    "img",
    "input",
    "ins",
    "kbd",
    "label",
    "legend",
    "li",
    "line",
    "linearGradient",
    "link",
    "main",
    "map",
    "mark",
    "marker",
    "marquee",
    "mask",
    "menu",
    "menuitem",
    "meta",
    "metadata",
    "meter",
    "mpath",
    "nav",
    "nobr",
    "noframes",
    "noscript",
    "object",
    "ol",
    "optgroup",
    "option",
    "output",
    "p",
    "param",
    "path",
    "pattern",
    "picture",
    "polygon",
    "polyline",
    "pre",
    "progress",
    "q",
    "radialGradient",
    "rect",
    "rp",
    "rt",
    "ruby",
    "s",
    "samp",
    "script",
    "search",
    "section",
    "select",
    "set",
    "slot",
    "small",
    "solidcolor",
    "source",
    "span",
    "stop",
    "strike",
    "strong",
    "style",
    "sub",
    "summary",
    "sup",
    "svg",
    "symbol",
    "table",
    "tbody",
    "td",
    "template",
    "text",
    "textPath",
    "textarea",
    "tfoot",
    "th",
    "thead",
    "time",
    "title",
    "tr",
    "track",
    "tspan",
    "tt",
    "u",
    "ul",
    "use",
    "var",
    "video",
    "view",
    "wbr",
];

/// In-place array mutations flagged on `this.state` chains (`S6746`).
pub(crate) const STATE_MUTATION_METHODS: [&str; 9] = [
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

/// Scans a `render` body for a return statement whose value subtree
/// contains JSX or a null literal (`S6435`).
#[derive(Default)]
pub(crate) struct RenderReturnScanner {
    pub(crate) satisfied: bool,
}

impl Visit<'_> for RenderReturnScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'_>) {
        if let Some(argument) = &it.argument {
            let mut probe = JsxOrNullScanner::default();
            probe.visit_expression(argument);
            self.satisfied |= probe.found;
        }
    }
}

/// Subtree probe for JSX elements, fragments, and null literals.
#[derive(Default)]
pub(crate) struct JsxOrNullScanner {
    pub(crate) found: bool,
}

impl Visit<'_> for JsxOrNullScanner {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if matches!(
            it,
            Expression::JSXElement(_) | Expression::JSXFragment(_) | Expression::NullLiteral(_)
        ) {
            self.found = true;
            return;
        }
        walk_expression(self, it);
    }
}

/// `S6791`: pre-16.3 lifecycle names superseded by `UNSAFE_`-prefixed ones.
pub(crate) const LEGACY_LIFECYCLE_METHODS: [&str; 3] = [
    "componentWillMount",
    "componentWillReceiveProps",
    "componentWillUpdate",
];

/// Whether a collected `propTypes` entry is declared `.isRequired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PropKind {
    Optional,
    Required,
}

/// One `.map(callback)` traversal frame: the callback's second parameter
/// name (the array index) and whether its root element was already checked.
pub(crate) struct MapFrame {
    pub(crate) index_param: Option<String>,
    pub(crate) root_checked: bool,
}

/// Frame for a `.map(callback)` traversal: remembers the callback's second
/// parameter (the array index) for `S6477`/`S6479`.
pub(crate) fn map_callback_frame(call: &CallExpression<'_>) -> Option<MapFrame> {
    let (property, _) = call_property(call)?;
    if property != "map" {
        return None;
    }
    let callback = call.arguments.first().and_then(argument_expression)?;
    let params = match callback {
        Expression::FunctionExpression(function) => &function.params,
        Expression::ArrowFunctionExpression(arrow) => &arrow.params,
        _ => return None,
    };
    let index_param = params
        .items
        .get(1)
        .and_then(|parameter| binding_identifier_name(&parameter.pattern))
        .map(str::to_string);
    Some(MapFrame {
        index_param,
        root_checked: false,
    })
}

/// Whether a `useXxx`-shaped callee names a hook.
pub(crate) fn call_argument_function_count(call: &CallExpression<'_>) -> usize {
    call.arguments
        .iter()
        .filter_map(argument_expression)
        .filter(|expression| {
            matches!(
                expression,
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            )
        })
        .count()
}

/// Component frame for a declarator-initialized function or arrow:
/// whether it returns JSX plus its binding span (`S6478`).
pub(crate) fn declarator_component_frame(
    declarator: &VariableDeclarator<'_>,
) -> Option<(bool, Span)> {
    let init = declarator.init.as_ref()?;
    if !matches!(
        init,
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    ) {
        return None;
    }
    let returns_jsx = expression_returns_jsx(init)?;
    let name_span = match &declarator.id {
        BindingPattern::BindingIdentifier(identifier) => identifier.span(),
        _ => declarator.span(),
    };
    Some((returns_jsx, name_span))
}

/// Whether a class renders (a `render` method returning JSX or null).
pub(crate) fn class_returns_jsx(class: &Class<'_>) -> bool {
    class.body.body.iter().any(|element| {
        let ClassElement::MethodDefinition(method) = element else {
            return false;
        };
        duplicated_key_name(&method.key) == Some("render")
            && method.kind == MethodDefinitionKind::Method
            && method
                .value
                .body
                .as_ref()
                .is_some_and(|body| body_returns_jsx(body))
    })
}

/// Whether a function-like body contains a return of JSX or null.
pub(crate) fn body_returns_jsx(body: &FunctionBody<'_>) -> bool {
    let mut scanner = RenderReturnScanner::default();
    scanner.visit_function_body(body);
    scanner.satisfied
}

/// First attribute with the given name on an opening tag, if any.
pub(crate) fn jsx_find_attribute<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a JSXAttribute<'a>> {
    opening.attributes.iter().find_map(|item| match item {
        JSXAttributeItem::Attribute(attribute) if jsx_attribute_name(attribute) == Some(name) => {
            Some(&**attribute)
        }
        _ => None,
    })
}

/// Property name of a `this.<property>` callee, if the call target is
/// exactly that shape.
pub(crate) fn callee_this_property<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    match &call.callee {
        Expression::StaticMemberExpression(member)
            if matches!(&member.object, Expression::ThisExpression(_)) =>
        {
            Some(&member.property.name)
        }
        _ => None,
    }
}

/// `setFoo` shape: a `set` prefix followed by an uppercase letter.
pub(crate) fn is_state_setter_name(name: &str) -> bool {
    name.strip_prefix("set")
        .is_some_and(|tail| tail.starts_with(|ch: char| ch.is_ascii_uppercase()))
}

/// `value` becomes `Value` (first ASCII letter uppercased).
pub(crate) fn capitalize_first(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Normalized key name for duplicate detection: static identifiers plus
/// their quoted-string spellings (`{a: 1, "a": 2}` collide).
pub(crate) fn duplicated_key_name<'data>(key: &PropertyKey<'data>) -> Option<&'data str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(identifier.name.as_str()),
        PropertyKey::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Whether a module export name spells `expected` (`import {a as b}` keeps
/// the imported spelling).
pub(crate) fn module_export_name_is(name: &ModuleExportName<'_>, expected: &str) -> bool {
    match name {
        ModuleExportName::IdentifierName(identifier) => identifier.name == expected,
        ModuleExportName::IdentifierReference(reference) => reference.name == expected,
        ModuleExportName::StringLiteral(literal) => literal.value == expected,
    }
}

/// Whether a member chain passes through a `this.state` link (`S6746`).
pub(crate) fn expression_through_this_state(expression: &Expression<'_>) -> bool {
    expression_through_this_link(expression, "state")
}

/// Tag name of a JSX element when spelled as a plain identifier (`div`,
/// `Widget`); namespaced, member, and `this` names have none.
pub(crate) fn jsx_element_tag<'a>(name: &'a JSXElementName<'a>) -> Option<&'a str> {
    match name {
        JSXElementName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXElementName::IdentifierReference(reference) => Some(&reference.name),
        _ => None,
    }
}

/// Whether a tag starts lowercase (intrinsic HTML/SVG spelling).
pub(crate) fn jsx_tag_is_intrinsic(tag: &str) -> bool {
    tag.starts_with(|ch: char| ch.is_ascii_lowercase())
}

/// Whether the opening tag carries a spread attribute (unknown props).
pub(crate) fn jsx_has_spread_attribute(opening: &JSXOpeningElement<'_>) -> bool {
    opening
        .attributes
        .iter()
        .any(|item| matches!(item, JSXAttributeItem::SpreadAttribute(_)))
}

/// Element tag behind a child position, if it is a plain element.
pub(crate) fn jsx_child_element_tag<'a>(child: &'a JSXChild<'a>) -> Option<&'a str> {
    match child {
        JSXChild::Element(element) => jsx_element_tag(&element.opening_element.name),
        _ => None,
    }
}

/// Tag name of a JSX attribute (`ref`, `children`, ...); namespaced names
/// (`xlink:href`) have no plain name.
pub(crate) fn jsx_attribute_name<'a>(attribute: &'a JSXAttribute<'a>) -> Option<&'a str> {
    match &attribute.name {
        JSXAttributeName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXAttributeName::NamespacedName(_) => None,
    }
}

/// Whether an intrinsic-element attribute is a known DOM/React name
/// (`S6747`): table, configured extras, `data-*`/`aria-*`, and handlers.
pub(crate) fn attribute_is_known(name: &str, whitelist: &[String]) -> bool {
    name.starts_with("data-")
        || name.starts_with("aria-")
        || (name.starts_with("on") && name[2..].starts_with(|ch: char| ch.is_ascii_alphabetic()))
        || REACT_DOM_ATTRIBUTES.contains(&name)
        || whitelist.iter().any(|allowed| allowed == name)
}

/// Whether a member chain contains a link spelled `link`.
pub(crate) fn member_chain_has_link(expression: &Expression<'_>, link: &str) -> bool {
    match expression {
        Expression::StaticMemberExpression(member) => {
            member.property.name == link || member_chain_has_link(&member.object, link)
        }
        _ => false,
    }
}

/// Whether a member chain passes through a `this.<link>` access.
pub(crate) fn expression_through_this_link(expression: &Expression<'_>, link: &str) -> bool {
    match expression {
        Expression::StaticMemberExpression(member) => {
            (matches!(&member.object, Expression::ThisExpression(_))
                && member.property.name == link)
                || expression_through_this_link(&member.object, link)
        }
        Expression::ComputedMemberExpression(member) => {
            expression_through_this_link(&member.object, link)
        }
        Expression::PrivateFieldExpression(member) => {
            expression_through_this_link(&member.object, link)
        }
        _ => false,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_react_jsx_rules(ctx.program, ctx.source, ctx.index, ctx.language, ctx.rules)
}
