// Family walker for 'react_jsx' (generated).
use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::expression_returns_jsx;
use crate::rules::shared::argument_expression;
use crate::rules::shared::call_property;
use crate::rules::shared::duplicated_key_name;
use crate::rules::shared::expression_through_this_link;
use crate::support::IssueSink;
use crate::support::LineIndex;
use crate::support::binding_identifier_name;
use crate::support::identifier_name;
use hoonarqube_ir::Issue;
use oxc_allocator::ArenaVec;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::AssignmentOperator;
use oxc_ast::ast::BindingPattern;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Class;
use oxc_ast::ast::ClassElement;
use oxc_ast::ast::DoWhileStatement;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ExpressionStatement;
use oxc_ast::ast::ForInStatement;
use oxc_ast::ast::ForOfStatement;
use oxc_ast::ast::ForStatement;
use oxc_ast::ast::FunctionBody;
use oxc_ast::ast::IfStatement;
use oxc_ast::ast::ImportDeclaration;
use oxc_ast::ast::JSXAttribute;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXAttributeName;
use oxc_ast::ast::JSXChild;
use oxc_ast::ast::JSXElement;
use oxc_ast::ast::JSXElementName;
use oxc_ast::ast::JSXExpressionContainer;
use oxc_ast::ast::JSXFragment;
use oxc_ast::ast::JSXOpeningElement;
use oxc_ast::ast::JSXText;
use oxc_ast::ast::MethodDefinition;
use oxc_ast::ast::MethodDefinitionKind;
use oxc_ast::ast::ObjectPropertyKind;
use oxc_ast::ast::PropertyDefinition;
use oxc_ast::ast::ReturnStatement;
use oxc_ast::ast::SimpleAssignmentTarget;
use oxc_ast::ast::Statement;
use oxc_ast::ast::VariableDeclarator;
use oxc_ast::ast::WhileStatement;
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
fn check_react_jsx_rules(
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
        self.check_s6757_this_expression(it);
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
    /// `S6775` collection: records `X.propTypes` / `X.defaultProps`
    /// object assignments for the post-pass.
    fn collect_prop_metadata(&mut self, assignment: &AssignmentExpression<'_>) {
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
}

/// Which side of the prop-metadata cross-check an assignment feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropSide {
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
fn call_argument_function_count(call: &CallExpression<'_>) -> usize {
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
fn declarator_component_frame(declarator: &VariableDeclarator<'_>) -> Option<(bool, Span)> {
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
fn class_returns_jsx(class: &Class<'_>) -> bool {
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

/// Tag name of a JSX attribute (`ref`, `children`, ...); namespaced names
/// (`xlink:href`) have no plain name.
pub(crate) fn jsx_attribute_name<'a>(attribute: &'a JSXAttribute<'a>) -> Option<&'a str> {
    match &attribute.name {
        JSXAttributeName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXAttributeName::NamespacedName(_) => None,
    }
}

/// Whether a member chain contains a link spelled `link`.
fn member_chain_has_link(expression: &Expression<'_>, link: &str) -> bool {
    match expression {
        Expression::StaticMemberExpression(member) => {
            member.property.name == link || member_chain_has_link(&member.object, link)
        }
        _ => false,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_react_jsx_rules(ctx.program, ctx.source, ctx.index, ctx.language, ctx.rules)
}

#[cfg(test)]
mod tests {

    use crate::test_support::*;

    #[test]
    fn children_prop_conflicts_with_nested_children() {
        let both = jsx_keys("const el = <div children={<a/>}><b/></div>;\n");
        assert_eq!(count_key(&both, "javascript:S6748"), 1);

        let attribute_only = jsx_keys("const el = <div children={<a/>}/>;\n");
        assert_eq!(count_key(&attribute_only, "javascript:S6748"), 0);

        let nested_only = jsx_keys("const el = <div><b/></div>;\n");
        assert_eq!(count_key(&nested_only, "javascript:S6748"), 0);
    }

    #[test]
    fn children_and_raw_html_attributes_conflict() {
        let both = jsx_keys(
            "const el = <div children={<a/>} dangerouslySetInnerHTML={{__html: 'x'}}/>;\n",
        );
        assert_eq!(count_key(&both, "javascript:S6761"), 1);

        let raw_only = jsx_keys("const el = <div dangerouslySetInnerHTML={{__html: 'x'}}/>;\n");
        assert_eq!(count_key(&raw_only, "javascript:S6761"), 0);
    }

    #[test]
    fn single_child_fragments_are_flagged() {
        let element_child = jsx_keys("const el = <><span/></>;\n");
        assert_eq!(count_key(&element_child, "javascript:S6749"), 1);

        let expression_child = jsx_keys("let item = 1;\nconst el = <>{item}</>;\n");
        assert_eq!(count_key(&expression_child, "javascript:S6749"), 1);

        let two_children = jsx_keys("const el = <><span/><span/></>;\n");
        assert_eq!(count_key(&two_children, "javascript:S6749"), 0);

        let empty_fragment = jsx_keys("const el = <></>;\n");
        assert_eq!(count_key(&empty_fragment, "javascript:S6749"), 0);
    }

    #[test]
    fn consumed_render_results_are_flagged() {
        let consumed = jsx_keys("const el = ReactDOM.render(<span/>, node);\n");
        assert_eq!(count_key(&consumed, "javascript:S6750"), 1);

        let statement = jsx_keys("ReactDOM.render(<span/>, node);\n");
        assert_eq!(count_key(&statement, "javascript:S6750"), 0);
    }

    #[test]
    fn use_state_pairs_follow_naming_convention() {
        let symmetric = js_keys("const [count, setCount] = useState(0);\n");
        assert_eq!(count_key(&symmetric, "javascript:S6754"), 0);

        let asymmetric = js_keys("const [count, setValue] = useState(0);\n");
        assert_eq!(count_key(&asymmetric, "javascript:S6754"), 1);

        let missing_set_prefix = js_keys("const [count, countUpdated] = useState(0);\n");
        assert_eq!(count_key(&missing_set_prefix, "javascript:S6754"), 1);
    }

    #[test]
    fn noop_state_setters_are_flagged() {
        let self_assigning = js_keys("setCount(count);\n");
        assert_eq!(count_key(&self_assigning, "javascript:S6443"), 1);

        let updater = js_keys("setCount(count + 1);\n");
        assert_eq!(count_key(&updater, "javascript:S6443"), 0);

        let different_value = js_keys("setCount(other);\n");
        assert_eq!(count_key(&different_value, "javascript:S6443"), 0);
    }

    #[test]
    fn find_dom_node_calls_are_flagged() {
        let flagged = js_keys("ReactDOM.findDOMNode(this).focus();\n");
        assert_eq!(count_key(&flagged, "javascript:S6788"), 1);

        let other_root = js_keys("wrapper.findDOMNode(this);\n");
        assert_eq!(count_key(&other_root, "javascript:S6788"), 0);
    }

    #[test]
    fn is_mounted_calls_are_flagged() {
        let flagged = js_keys("if (this.isMounted()) {\n  done();\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6789"), 1);

        let other_object = js_keys("if (widget.isMounted()) {\n  done();\n}\n");
        assert_eq!(count_key(&other_object, "javascript:S6789"), 0);
    }

    #[test]
    fn string_refs_and_refs_accesses_are_flagged() {
        let string_ref = jsx_keys("const el = <input ref=\"name\"/>;\n");
        assert_eq!(count_key(&string_ref, "javascript:S6790"), 1);

        let callback_ref = jsx_keys("const el = <input ref={(node) => save(node)}/>;\n");
        assert_eq!(count_key(&callback_ref, "javascript:S6790"), 0);

        let refs_access = js_keys("this.refs.name.focus();\n");
        assert_eq!(count_key(&refs_access, "javascript:S6790"), 1);

        let refs_write = js_keys("this.refs.name = node;\n");
        assert_eq!(count_key(&refs_write, "javascript:S6790"), 1);

        let plain_member = js_keys("this.props.name.focus();\n");
        assert_eq!(count_key(&plain_member, "javascript:S6790"), 0);
    }

    #[test]
    fn legacy_lifecycle_methods_are_flagged() {
        let flagged = js_keys(
            "class A extends B {\n  componentWillMount() {}\n  componentDidMount() {}\n}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S6791"), 1);

        let safe = js_keys("class A extends B {\n  UNSAFE_componentWillMount() {}\n}\n");
        assert_eq!(count_key(&safe, "javascript:S6791"), 0);
    }

    #[test]
    fn deprecated_react_apis_are_flagged() {
        let prop_types_package = js_keys("import PropTypes from 'prop-types';\n");
        assert_eq!(count_key(&prop_types_package, "javascript:S6957"), 1);
        let create_class = js_keys("const x = React.createClass({});\n");
        assert_eq!(count_key(&create_class, "javascript:S6957"), 1);

        let render_call = jsx_keys("ReactDOM.render(<span/>, node);\n");
        assert_eq!(count_key(&render_call, "javascript:S6957"), 1);

        let current_api =
            js_keys("import React from 'react';\nconst x = React.createElement('div');\n");
        assert_eq!(count_key(&current_api, "javascript:S6957"), 0);
    }

    #[test]
    fn pure_component_update_is_useless() {
        let flagged = js_keys(
            "class A extends PureComponent {\n  shouldComponentUpdate() {\n    return true;\n  }\n}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S6763"), 1);

        let plain_component = js_keys(
            "class A extends Component {\n  shouldComponentUpdate() {\n    return true;\n  }\n}\n",
        );
        assert_eq!(count_key(&plain_component, "javascript:S6763"), 0);
    }

    #[test]
    fn direct_state_mutations_are_flagged() {
        let method_mutation = js_keys("this.state.items.push(1);\n");
        assert_eq!(count_key(&method_mutation, "javascript:S6746"), 1);

        let field_write = js_keys("this.state.count = 5;\n");
        assert_eq!(count_key(&field_write, "javascript:S6746"), 1);

        let copy_first = js_keys("const copy = [...this.state.items];\ncopy.push(1);\n");
        assert_eq!(count_key(&copy_first, "javascript:S6746"), 0);

        let props_chain = js_keys("this.props.items.push(1);\n");
        assert_eq!(count_key(&props_chain, "javascript:S6746"), 0);
    }

    #[test]
    fn unescaped_jsx_entities_are_flagged() {
        // oxc's JSX lexer rejects raw `>` and `}` in text (tolerant parse
        // recovers with no AST), so the flaggable surface is quote marks.
        let double_quoted = jsx_keys("const el = <div>say \"hi\"</div>;\n");
        assert_eq!(count_key(&double_quoted, "javascript:S6766"), 1);

        let apostrophe = jsx_keys("const el = <div>it's here</div>;\n");
        assert_eq!(count_key(&apostrophe, "javascript:S6766"), 1);

        let plain_text = jsx_keys("const el = <div>plain text</div>;\n");
        assert_eq!(count_key(&plain_text, "javascript:S6766"), 0);
    }

    #[test]
    fn empty_containers_without_comments_are_flagged() {
        let empty = jsx_keys("const el = <div>{}</div>;\n");
        assert_eq!(count_key(&empty, "javascript:S6438"), 1);

        let commented = jsx_keys("const el = <div>{/* note */}</div>;\n");
        assert_eq!(count_key(&commented, "javascript:S6438"), 0);
    }

    #[test]
    fn inline_function_props_are_flagged() {
        let arrow_value = jsx_keys("const el = <button onClick={() => save()}/>;\n");
        assert_eq!(count_key(&arrow_value, "javascript:S6480"), 1);

        let bound_value = jsx_keys("const el = <button onClick={handler.bind(this)}/>;\n");
        assert_eq!(count_key(&bound_value, "javascript:S6480"), 1);

        let reference_value = jsx_keys("const el = <button onClick={handler}/>\n;\n");
        assert_eq!(count_key(&reference_value, "javascript:S6480"), 0);
    }

    #[test]
    fn map_index_keys_and_missing_keys_are_flagged() {
        let index_key = jsx_keys("items.map((item, index) => <li key={index}/>);\n");
        assert_eq!(count_key(&index_key, "javascript:S6479"), 1);
        assert_eq!(count_key(&index_key, "javascript:S6477"), 0);

        let stable_key = jsx_keys("items.map((item) => <li key={item.id}/>);\n");
        assert_eq!(count_key(&stable_key, "javascript:S6479"), 0);

        let missing_key = jsx_keys("items.map((item, index) => <li/>);\n");
        assert_eq!(count_key(&missing_key, "javascript:S6477"), 1);
    }

    #[test]
    fn unknown_lowercase_tags_are_flagged() {
        let unknown = jsx_keys("const el = <widget/>;\n");
        assert_eq!(count_key(&unknown, "javascript:S6770"), 1);

        let intrinsic = jsx_keys("const el = <div/>;\n");
        assert_eq!(count_key(&intrinsic, "javascript:S6770"), 0);

        let custom_element = jsx_keys("const el = <my-widget/>;\n");
        assert_eq!(count_key(&custom_element, "javascript:S6770"), 0);

        let component = jsx_keys("const el = <Widget/>;\n");
        assert_eq!(count_key(&component, "javascript:S6770"), 0);
    }

    #[test]
    fn render_methods_must_return_jsx_or_null() {
        let returns_jsx = js_keys("class A {\n  render() {\n    return <span/>;\n  }\n}\n");
        assert_eq!(count_key(&returns_jsx, "javascript:S6435"), 0);

        let returns_nothing = js_keys("class A {\n  render() {\n    console.log(1);\n  }\n}\n");
        assert_eq!(count_key(&returns_nothing, "javascript:S6435"), 1);

        let conditional_null = js_keys(
            "class A {\n  render() {\n    if (done) {\n      return null;\n    }\n    return <span/>;\n  }\n}\n",
        );
        assert_eq!(count_key(&conditional_null, "javascript:S6435"), 0);
    }

    #[test]
    fn literal_conditionals_rendering_children_are_flagged() {
        let numeric_guard = jsx_keys("const el = <div>{5 && <span/>}</div>;\n");
        assert_eq!(count_key(&numeric_guard, "javascript:S6439"), 1);

        let string_guard = jsx_keys("const el = <div>{'x' && <span/>}</div>;\n");
        assert_eq!(count_key(&string_guard, "javascript:S6439"), 1);

        let boolean_guard =
            jsx_keys("let ready = true;\nconst el = <div>{ready && <span/>}</div>;\n");
        assert_eq!(count_key(&boolean_guard, "javascript:S6439"), 0);

        let attribute_position = jsx_keys("const el = <div prop={5 && <span/>}/>;\n");
        assert_eq!(count_key(&attribute_position, "javascript:S6439"), 0);
    }

    #[test]
    fn hook_calls_under_conditions_are_flagged() {
        let under_if = js_keys("function C() {\n  if (ready) {\n    useState();\n  }\n}\n");
        assert_eq!(count_key(&under_if, "javascript:S6440"), 1);

        let under_loop = js_keys("for (const item of items) {\n  useState();\n}\n");
        assert_eq!(count_key(&under_loop, "javascript:S6440"), 1);

        let in_callback = js_keys("useEffect(() => {\n  useState();\n}, []);\n");
        assert_eq!(count_key(&in_callback, "javascript:S6440"), 1);

        let top_level = js_keys("function Component() {\n  const [v] = useState(0);\n}\n");
        assert_eq!(count_key(&top_level, "javascript:S6440"), 0);
    }

    #[test]
    fn undestructured_use_state_is_flagged() {
        let plain_binding = js_keys("const state = useState(0);\n");
        assert_eq!(count_key(&plain_binding, "javascript:S6442"), 1);

        let destructured = js_keys("const [value, setValue] = useState(0);\n");
        assert_eq!(count_key(&destructured, "javascript:S6442"), 0);
    }

    #[test]
    fn inline_context_values_are_flagged() {
        let object_value = jsx_keys("const el = <Ctx.Provider value={{a: 1}}/>;\n");
        assert_eq!(count_key(&object_value, "javascript:S6481"), 1);

        let array_value = jsx_keys("const el = <Ctx.Provider value={[1]}/>\n;\n");
        assert_eq!(count_key(&array_value, "javascript:S6481"), 1);

        let stable_value = jsx_keys("let memo = {};\nconst el = <Ctx.Provider value={memo}/>\n;\n");
        assert_eq!(count_key(&stable_value, "javascript:S6481"), 0);
    }

    #[test]
    fn nested_component_definitions_are_flagged() {
        let nested = jsx_keys(
            "function Outer() {\n  function Inner() {\n    return <span/>;\n  }\n  return <Inner/>;\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S6478"), 1);

        let siblings = jsx_keys(
            "function Outer() {\n  return <span/>;\n}\nfunction Inner() {\n  return <span/>;\n}\n",
        );
        assert_eq!(count_key(&siblings, "javascript:S6478"), 0);
    }

    #[test]
    fn set_state_reading_state_is_flagged() {
        let direct_read = js_keys("this.setState({count: this.state.count + 1});\n");
        assert_eq!(count_key(&direct_read, "javascript:S6756"), 1);

        let updater = js_keys("this.setState((previous) => ({count: previous.count + 1}));\n");
        assert_eq!(count_key(&updater, "javascript:S6756"), 0);
    }

    #[test]
    fn this_in_functional_components_is_flagged() {
        let flagged = jsx_keys(
            "function Component() {\n  return <button onClick={() => this.save()}/>;\n}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S6757"), 1);

        let class_method = js_keys("class Widget {\n  save() {\n    this.x();\n  }\n}\n");
        assert_eq!(count_key(&class_method, "javascript:S6757"), 0);
    }

    #[test]
    fn collapsing_whitespace_between_inline_siblings_is_flagged() {
        let inline_gap = jsx_keys("const el = <div><span>a</span> <b>c</b></div>;\n");
        assert_eq!(count_key(&inline_gap, "javascript:S6772"), 1);

        let block_elements = jsx_keys("const el = <div><p>a</p> <p>b</p></div>;\n");
        assert_eq!(count_key(&block_elements, "javascript:S6772"), 0);
    }

    #[test]
    fn props_without_prop_types_flagged_javascript_only() {
        let flagged = js_keys("class A {\n  m() {\n    return this.props.x;\n  }\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6774"), 1);

        let declared = js_keys(
            "class A {\n  static propTypes = {};\n  m() {\n    return this.props.x;\n  }\n}\n",
        );
        assert_eq!(count_key(&declared, "javascript:S6774"), 0);

        let typescript_report = ts("class A {\n  m() {\n    return this.props.x;\n  }\n}\n");
        assert_eq!(
            count_key(&report_keys(&typescript_report), "typescript:S6774"),
            0
        );
    }

    #[test]
    fn default_props_require_matching_required_prop_types() {
        let missing_entry = js_keys(
            "C.propTypes = {a: PropTypes.string.isRequired};\nC.defaultProps = {a: 'x', b: 'y'};\n",
        );
        assert_eq!(count_key(&missing_entry, "javascript:S6775"), 1);

        let optional_entry =
            js_keys("C.propTypes = {a: PropTypes.string};\nC.defaultProps = {a: 'x'};\n");
        assert_eq!(count_key(&optional_entry, "javascript:S6775"), 1);

        let covered = js_keys(
            "C.propTypes = {a: PropTypes.string.isRequired};\nC.defaultProps = {a: 'x'};\n",
        );
        assert_eq!(count_key(&covered, "javascript:S6775"), 0);
    }

    #[test]
    fn unknown_jsx_attributes_are_flagged() {
        let html_spelling = jsx_keys("const el = <div class=\"x\"/>;\n");
        assert_eq!(count_key(&html_spelling, "javascript:S6747"), 1);

        let unknown_name = jsx_keys("const el = <div foo=\"1\"/>;\n");
        assert_eq!(count_key(&unknown_name, "javascript:S6747"), 1);

        let known_names = jsx_keys(
            "const el = <div className=\"x\" tabIndex={0} data-x=\"1\" aria-hidden=\"true\" onClick={f}/>;\n",
        );
        assert_eq!(count_key(&known_names, "javascript:S6747"), 0);

        let rules = RuleOptions {
            jsx_attribute_whitelist: vec!["foo".to_string()],
            ..RuleOptions::default()
        };
        let whitelisted = keys_with_rules("<div foo=\"1\"/>\n", &rules);
        assert_eq!(count_key(&whitelisted, "javascript:S6747"), 0);

        let on_component = jsx_keys("const el = <Widget arbitraryProp=\"1\"/>;\n");
        assert_eq!(count_key(&on_component, "javascript:S6747"), 0);
    }
}
