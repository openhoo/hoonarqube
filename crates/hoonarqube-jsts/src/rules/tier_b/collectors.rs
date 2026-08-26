// Residual rule machinery for 'tier_b' (extracted from lib.rs).
use crate::engine::scope_model::callee_member_name;
use crate::engine::scope_model::member_optional;
use crate::engine::scope_model::tb_assignment_target;
use crate::rules::shared::SHELL_EXEC_FUNCTIONS;
use crate::rules::shared::duplicated_key_name;
use crate::rules::shared::expression_through_this_link;
use crate::rules::shared::is_unpinned_npm_install;
use crate::rules::shared::regex_pattern_text;
use crate::rules::shared::static_command_text;
use crate::rules::tier_b::s2077_tb_sql_injection::SqlInjectionCollector;
use crate::rules::tier_b::s2259_tb_null_accesses::NullAccessCollector;
use crate::rules::tier_b::s2589_tb_constant_conditions::ConstantConditionCollector;
use crate::rules::tier_b::s2933_tb_readonly_candidate_fields::ReadonlyFieldCollector;
use crate::rules::tier_b::s3353_tb_let_to_const::LetToConstCollector;
use crate::rules::tier_b::s4030_tb_useless_collections::UselessCollectionCollector;
use crate::rules::tier_b::s4043_tb_in_place_captures::InPlaceCaptureCollector;
use crate::rules::tier_b::s4143_tb_map_round_trips::MapRoundTripCollector;
use crate::rules::tier_b::s4784_tb_dynamic_regexps::DynamicRegexCollector;
use crate::rules::tier_b::s5443_tb_permissive_file_access::PermissiveAccessCollector;
use crate::rules::tier_b::s5725_tb_shell_commands::ShellCommandCollector;
use crate::rules::tier_b::s5860_tb_named_groups::NamedGroupCollector;
use crate::rules::tier_b::s5876_tb_session_regeneration::SessionRegenerationCollector;
use crate::rules::tier_b::s6486_tb_unstable_keys::UnstableKeyCollector;
use crate::rules::tier_b::s6544_tb_promise_chains::PromiseChainCollector;
use crate::support::IssueSink;
use crate::support::ast::callee_name;
use crate::support::ast::expression_root_name;
use crate::support::member_object;
use crate::support::property_key_name;
use crate::support::static_property_name;
use crate::support::unparenthesized;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::AssignmentOperator;
use oxc_ast::ast::BindingPattern;
use oxc_ast::ast::ConditionalExpression;
use oxc_ast::ast::Declaration;
use oxc_ast::ast::DoWhileStatement;
use oxc_ast::ast::ExportDeclaration;
use oxc_ast::ast::ForInStatement;
use oxc_ast::ast::ForOfStatement;
use oxc_ast::ast::ForStatementLeft;
use oxc_ast::ast::IfStatement;
use oxc_ast::ast::JSXAttribute;
use oxc_ast::ast::JSXAttributeName;
use oxc_ast::ast::JSXAttributeValue;
use oxc_ast::ast::SimpleAssignmentTarget;
use oxc_ast::ast::SwitchStatement;
use oxc_ast::ast::UpdateExpression;
use oxc_ast::ast::VariableDeclaration;
use oxc_ast::ast::VariableDeclarationKind;
use oxc_ast::ast::VariableDeclarator;
use oxc_ast::ast::WhileStatement;
use oxc_ast::ast::{
    Argument, ArrayExpression, ArrayExpressionElement, ArrowFunctionBody, AssignmentTarget,
    BinaryOperator, CallExpression, Class, Expression, FormalParameters, MemberExpression,
    MethodDefinition, MethodDefinitionKind, NewExpression, ObjectExpression, ObjectPropertyKind,
    PropertyDefinition, PropertyKey, RegExpLiteral, Statement, TSAccessibility,
};
use oxc_ast::ast::{
    ArrayPattern, ExportNamedDeclaration, ImportDeclaration, ObjectPattern,
    TSTypeParameterDeclaration, TSTypeParameterInstantiation,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_array_pattern;
use oxc_ast_visit::walk::walk_assignment_expression;
use oxc_ast_visit::walk::walk_conditional_expression;
use oxc_ast_visit::walk::walk_declaration;
use oxc_ast_visit::walk::walk_do_while_statement;
use oxc_ast_visit::walk::walk_export_named_declaration;
use oxc_ast_visit::walk::walk_for_in_statement;
use oxc_ast_visit::walk::walk_for_of_statement;
use oxc_ast_visit::walk::walk_if_statement;
use oxc_ast_visit::walk::walk_import_declaration;
use oxc_ast_visit::walk::walk_object_pattern;
use oxc_ast_visit::walk::walk_switch_statement;
use oxc_ast_visit::walk::walk_ts_type_parameter_declaration;
use oxc_ast_visit::walk::walk_ts_type_parameter_instantiation;
use oxc_ast_visit::walk::walk_update_expression;
use oxc_ast_visit::walk::walk_variable_declaration;
use oxc_ast_visit::walk::walk_variable_declarator;
use oxc_ast_visit::walk::walk_while_statement;
use oxc_ast_visit::walk::{
    walk_array_expression, walk_call_expression, walk_class, walk_formal_parameters,
    walk_member_expression, walk_method_definition, walk_new_expression, walk_object_expression,
    walk_property_definition,
};
use oxc_span::{GetSpan, Span};

#[derive(Default)]
pub(crate) struct ClassFrame {
    pub(crate) super_name: Option<String>,
    /// Instance methods declared on the class (`S6441`).
    pub(crate) methods: Vec<(String, Span)>,
    /// `#field` / `private` members (`S1068`).
    pub(crate) private_members: Vec<(String, Span)>,
    /// Keys of a static `propTypes = {…}` object (`S6767`).
    pub(crate) prop_type_keys: Vec<(String, Span)>,
    /// Identity assigned per pushed class, used to attribute member usages.
    pub(crate) frame_id: usize,
}

/// One file-wide pass collecting private members, component methods, and
/// `propTypes` keys together with every member-property name used, each
/// attributed to its innermost enclosing class (`None` = outside any class)
/// so unrelated classes cannot suppress each other's findings.
pub(crate) struct ClassRuleCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) frames: Vec<ClassFrame>,
    /// Exited class frames, kept for deferred finishing after the whole
    /// program was visited (post-class usages must be visible by then).
    pub(crate) finished_frames: Vec<ClassFrame>,
    pub(crate) next_frame_id: usize,
    /// Member names are arena-backed and outlive the traversal.
    pub(crate) used_properties: Vec<(&'a str, Option<usize>)>,
    pub(crate) props_accessed: Vec<(&'a str, Option<usize>)>,
}

impl<'a> Visit<'a> for ClassRuleCollector<'a, '_> {
    fn visit_class(&mut self, class: &Class<'a>) {
        let super_name = class
            .heritage
            .as_ref()
            .and_then(|heritage| match &heritage.expression {
                Expression::Identifier(name) => Some(name.name.to_string()),
                _ => None,
            });
        let frame_id = self.next_frame_id;
        self.next_frame_id += 1;
        self.frames.push(ClassFrame {
            super_name,
            frame_id,
            ..ClassFrame::default()
        });
        oxc_ast_visit::walk::walk_class(self, class);
        let frame = self.frames.pop().expect("class frame pushed above");
        self.finished_frames.push(frame);
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        if let Some(name) = property_key_name(&method.key)
            && let Some(frame) = self.frames.last_mut()
        {
            if !method.r#static && method.kind == MethodDefinitionKind::Method {
                frame.methods.push((name.to_string(), method.span));
            }
            if method.accessibility == Some(TSAccessibility::Private) {
                frame.private_members.push((name.to_string(), method.span));
            }
        }
        oxc_ast_visit::walk::walk_method_definition(self, method);
    }

    fn visit_property_definition(&mut self, definition: &oxc_ast::ast::PropertyDefinition<'a>) {
        let name = property_key_name(&definition.key);
        if let Some(frame) = self.frames.last_mut() {
            match &definition.key {
                PropertyKey::PrivateIdentifier(ident) => {
                    frame
                        .private_members
                        .push((ident.name.to_string(), definition.span));
                }
                _ => {
                    if definition.accessibility == Some(TSAccessibility::Private)
                        && let Some(name) = name
                    {
                        frame
                            .private_members
                            .push((name.to_string(), definition.span));
                    }
                }
            }
            if definition.r#static
                && name.is_some_and(|key| key == "propTypes")
                && let Some(Expression::ObjectExpression(object)) =
                    definition.value.as_ref().map(unparenthesized)
            {
                for property in &object.properties {
                    if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) = property
                        && let Some(key) = property_key_name(&property.key)
                    {
                        frame
                            .prop_type_keys
                            .push((key.to_string(), property.key.span()));
                    }
                }
            }
        }
        oxc_ast_visit::walk::walk_property_definition(self, definition);
    }

    fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
        let context = self.frames.last().map(|frame| frame.frame_id);
        if let Some(name) = static_property_name(member) {
            self.used_properties.push((name, context));
            if expression_through_this_link(member.object(), "props") {
                self.props_accessed.push((name, context));
            }
        }
        if let MemberExpression::PrivateFieldExpression(field) = member {
            self.used_properties
                .push((field.field.name.as_str(), context));
        }
        oxc_ast_visit::walk::walk_member_expression(self, member);
    }
}

/// All Tier-B checks that run over the scope model.
const SQL_SINK_METHODS: [&str; 3] = ["query", "execute", "exec"];

const WRITE_ONLY_METHODS: [&str; 4] = ["push", "unshift", "set", "add"];

const IN_PLACE_ARRAY_METHODS: [&str; 4] = ["sort", "reverse", "splice", "fill"];

const FS_WRITE_FUNCTIONS: [&str; 7] = [
    "open",
    "openSync",
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "mkdir",
];

fn is_dynamic_sql(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::TemplateLiteral(template) => !template.expressions.is_empty(),
        Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
            sql_operand_is_untrusted(&binary.left) || sql_operand_is_untrusted(&binary.right)
        }
        _ => false,
    }
}

fn sql_operand_is_untrusted(expression: &Expression<'_>) -> bool {
    !matches!(
        unparenthesized(expression),
        Expression::StringLiteral(_) | Expression::NumericLiteral(_)
    )
}

fn is_empty_collection_init(init: &Expression<'_>) -> bool {
    match init {
        Expression::ArrayExpression(array) => array.elements.is_empty(),
        Expression::ObjectExpression(object) => object.properties.is_empty(),
        Expression::NewExpression(new_expression) => {
            new_expression.arguments.is_empty()
                && matches!(
                    &new_expression.callee,
                    Expression::Identifier(callee)
                        if callee.name == "Map" || callee.name == "Set"
                )
        }
        _ => false,
    }
}

/// `(receiver name, receiver span, method)` of `x.sort()`-style calls.
pub(crate) fn in_place_array_call<'data>(
    call: &CallExpression<'data>,
) -> Option<(&'data str, Span, &'data str)> {
    let member = call.callee.as_member_expression()?;
    let name = static_property_name(member)?;
    if !IN_PLACE_ARRAY_METHODS.contains(&name) {
        return None;
    }
    match member_object(member) {
        Expression::Identifier(base) => Some((base.name.as_str(), base.span(), name)),
        _ => None,
    }
}

fn tmpdir_path(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::StringLiteral(literal) => literal.value.contains("/tmp"),
        Expression::TemplateLiteral(template) => {
            template
                .quasis
                .iter()
                .any(|quasi| quasi.value.raw.contains("/tmp"))
                || template.expressions.iter().any(tmpdir_path)
        }
        Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
            tmpdir_path(&binary.left) || tmpdir_path(&binary.right)
        }
        Expression::CallExpression(call) => {
            callee_member_name(call) == Some("tmpdir")
                && matches!(
                    call.callee.as_member_expression().map(member_object),
                    Some(Expression::Identifier(object)) if object.name == "os"
                )
        }
        _ => false,
    }
}

fn has_exclusive_flag(call: &CallExpression<'_>) -> bool {
    call.arguments.iter().skip(1).any(|argument| {
        argument
            .as_expression()
            .is_some_and(|expression| flag_grants_exclusive(unparenthesized(expression)))
    })
}

fn flag_grants_exclusive(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::StringLiteral(literal) => literal.value.contains('x'),
        Expression::ObjectExpression(object) => object.properties.iter().any(|property| {
            matches!(
                property,
                ObjectPropertyKind::ObjectProperty(prop)
                    if duplicated_key_name(&prop.key) == Some("flag")
                        && matches!(
                            unparenthesized(&prop.value),
                            Expression::StringLiteral(literal) if literal.value.contains('x')
                        )
            )
        }),
        _ => false,
    }
}

/// `(property name, property span)` when an assignment targets `this.X`.
fn this_member_target<'d>(target: &AssignmentTarget<'d>) -> Option<(&'d str, Span)> {
    let AssignmentTarget::StaticMemberExpression(member) = target else {
        return None;
    };
    if !matches!(&member.object, Expression::ThisExpression(_)) {
        return None;
    }
    Some((member.property.name.as_str(), member.property.span()))
}

fn is_static_regex_source(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::StringLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::NumericLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
            is_static_regex_source(&binary.left) && is_static_regex_source(&binary.right)
        }
        _ => false,
    }
}

fn is_login_path(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::StringLiteral(literal) => {
            let path = literal.value.to_ascii_lowercase();
            path.contains("login")
                || path.contains("signin")
                || path.contains("sign-in")
                || path.contains("auth")
        }
        _ => false,
    }
}

pub(crate) fn unstable_key_call(call: &CallExpression<'_>) -> bool {
    let Some(member) = call.callee.as_member_expression() else {
        return false;
    };
    match (member_object(member), static_property_name(member)) {
        (Expression::Identifier(object), Some(property)) => {
            (object.name == "Math" && property == "random")
                || (object.name == "Date" && property == "now")
        }
        _ => false,
    }
}

/// Whether the first argument of a `.then(...)` call yields no value.
pub(crate) fn then_callback_returns_nothing(call: &CallExpression<'_>) -> bool {
    let Some(argument) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return false;
    };
    let statements = match unparenthesized(argument) {
        Expression::ArrowFunctionExpression(arrow) => {
            if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                Some(&body.statements)
            } else {
                None
            }
        }
        Expression::FunctionExpression(function) => {
            function.body.as_ref().map(|body| &body.statements)
        }
        _ => None,
    };
    match statements {
        Some(statements) => !statements.iter().any(|statement| {
            matches!(
                statement,
                Statement::ReturnStatement(return_statement)
                    if return_statement.argument.is_some()
            )
        }),
        None => false,
    }
}

/// Element/container shapes examined for trailing commas.
pub(crate) struct TrailingCommaList {
    /// Full container span, ending in `'('`, `'['`, `'{'`, `'>'`, or — for
    /// import/export specifier lists — one past their closing `'}'`.
    pub(crate) container: Span,
    /// Last element span, when the list has elements and no rest.
    pub(crate) last_element: Option<Span>,
}

pub(crate) struct TrailingCommaListCollector<'p> {
    pub(crate) lists: Vec<TrailingCommaList>,
    /// Raw source bytes; specifier-list declaration spans end past their
    /// closing brace, so the byte offset is located on demand.
    pub(crate) source: &'p [u8],
}

impl<'p> Visit<'p> for TrailingCommaListCollector<'p> {
    fn visit_array_expression(&mut self, array: &ArrayExpression<'p>) {
        let spread_last = matches!(
            array.elements.last(),
            Some(ArrayExpressionElement::SpreadElement(_))
        );
        let last = (!spread_last)
            .then(|| array.elements.last())
            .flatten()
            .map(GetSpan::span);
        self.lists.push(TrailingCommaList {
            container: array.span,
            last_element: last,
        });
        walk_array_expression(self, array);
    }

    fn visit_object_expression(&mut self, object: &ObjectExpression<'p>) {
        self.lists.push(TrailingCommaList {
            container: object.span,
            last_element: object.properties.last().map(GetSpan::span),
        });
        walk_object_expression(self, object);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        self.note_arguments(call.span, &call.arguments);
        walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, new_expression: &NewExpression<'p>) {
        self.note_arguments(new_expression.span, &new_expression.arguments);
        walk_new_expression(self, new_expression);
    }

    fn visit_formal_parameters(&mut self, parameters: &FormalParameters<'p>) {
        if parameters.rest.is_none() {
            self.lists.push(TrailingCommaList {
                container: parameters.span,
                last_element: parameters.items.last().map(GetSpan::span),
            });
        }
        walk_formal_parameters(self, parameters);
    }

    fn visit_array_pattern(&mut self, pattern: &ArrayPattern<'p>) {
        if pattern.rest.is_none() {
            let last = pattern.elements.last().and_then(|element| element.as_ref());
            self.lists.push(TrailingCommaList {
                container: pattern.span,
                last_element: last.map(GetSpan::span),
            });
        }
        walk_array_pattern(self, pattern);
    }

    fn visit_object_pattern(&mut self, pattern: &ObjectPattern<'p>) {
        if pattern.rest.is_none() {
            self.lists.push(TrailingCommaList {
                container: pattern.span,
                last_element: pattern.properties.last().map(GetSpan::span),
            });
        }
        walk_object_pattern(self, pattern);
    }

    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'p>) {
        if let Some(specifiers) = &declaration.specifiers
            && let (Some(first), Some(last)) = (specifiers.first(), specifiers.last())
            && let Some(closer_end) = self.closing_brace_end(last.span().end)
        {
            self.lists.push(TrailingCommaList {
                container: Span::new(first.span().start, closer_end),
                last_element: Some(last.span()),
            });
        }
        walk_import_declaration(self, declaration);
    }

    fn visit_export_named_declaration(&mut self, declaration: &ExportNamedDeclaration<'p>) {
        if let (Some(first), Some(last)) = (
            declaration.specifiers.first(),
            declaration.specifiers.last(),
        ) && let Some(closer_end) = self.closing_brace_end(last.span().end)
        {
            self.lists.push(TrailingCommaList {
                container: Span::new(first.span().start, closer_end),
                last_element: Some(last.span()),
            });
        }
        walk_export_named_declaration(self, declaration);
    }

    fn visit_ts_type_parameter_declaration(
        &mut self,
        declaration: &TSTypeParameterDeclaration<'p>,
    ) {
        self.lists.push(TrailingCommaList {
            container: declaration.span,
            last_element: declaration.params.last().map(GetSpan::span),
        });
        walk_ts_type_parameter_declaration(self, declaration);
    }

    fn visit_ts_type_parameter_instantiation(
        &mut self,
        instantiation: &TSTypeParameterInstantiation<'p>,
    ) {
        self.lists.push(TrailingCommaList {
            container: instantiation.span,
            last_element: instantiation.params.last().map(GetSpan::span),
        });
        walk_ts_type_parameter_instantiation(self, instantiation);
    }
}

/// The `S1438` skip note above explains why no semicolon findings are emitted;
/// this collector only feeds the trailing-comma checks.
impl<'p> TrailingCommaListCollector<'p> {
    /// Constructs a collector over raw source bytes.
    pub(crate) fn new(source: &'p str) -> Self {
        Self {
            lists: Vec::new(),
            source: source.as_bytes(),
        }
    }

    /// Offset one past the first `}` at or after `from`. Nothing but
    /// whitespace or comments can legally precede the list-closing brace.
    fn closing_brace_end(&self, from: u32) -> Option<u32> {
        let rest = self.source.get(from as usize..)?;
        let index = rest.iter().position(|byte| *byte == b'}')?;
        let offset = u32::try_from(index).ok()?;
        Some(from + offset + 1)
    }
    fn note_arguments(&mut self, container: Span, arguments: &[Argument<'_>]) {
        let spread_last = matches!(arguments.last(), Some(Argument::SpreadElement(_)));
        let last = (!spread_last)
            .then(|| arguments.last())
            .flatten()
            .and_then(Argument::as_expression)
            .map(GetSpan::span);
        self.lists.push(TrailingCommaList {
            container,
            last_element: last,
        });
    }
}

impl<'a> Visit<'a> for NamedGroupCollector {
    fn visit_reg_exp_literal(&mut self, literal: &RegExpLiteral<'a>) {
        self.literals
            .push((literal.span, regex_pattern_text(literal).to_string()));
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(member) = call.callee.as_member_expression()
            && let Some(name) = static_property_name(member)
        {
            // Regex literal as the `.exec` receiver: `RegExp.prototype.exec`
            // takes the subject as argument and returns a result exposing
            // `groups`.
            if name == "exec"
                && let Expression::RegExpLiteral(regexp) = unparenthesized(member_object(member))
            {
                self.grouped_literals.push(regexp.span);
            }
            // Regex literal as argument 0 of `String.prototype.match`/
            // `.matchAll`, whose result also exposes `groups`.
            if matches!(name, "match" | "matchAll")
                && let Some(argument) = call.arguments.first()
                && let Some(expression) = argument.as_expression()
                && let Expression::RegExpLiteral(regexp) = unparenthesized(expression)
            {
                self.grouped_literals.push(regexp.span);
            }
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

impl ConstantConditionCollector {
    fn note_test(&mut self, test: &Expression<'_>) {
        if let Expression::BooleanLiteral(literal) = unparenthesized(test) {
            self.sites.push((literal.span, literal.value));
        }
    }
}

impl<'a> Visit<'a> for ConstantConditionCollector {
    fn visit_if_statement(&mut self, node: &IfStatement<'a>) {
        self.note_test(&node.test);
        walk_if_statement(self, node);
    }

    fn visit_while_statement(&mut self, node: &WhileStatement<'a>) {
        self.note_test(&node.test);
        walk_while_statement(self, node);
    }

    fn visit_do_while_statement(&mut self, node: &DoWhileStatement<'a>) {
        self.note_test(&node.test);
        walk_do_while_statement(self, node);
    }

    fn visit_conditional_expression(&mut self, node: &ConditionalExpression<'a>) {
        self.note_test(&node.test);
        walk_conditional_expression(self, node);
    }

    fn visit_switch_statement(&mut self, node: &SwitchStatement<'a>) {
        self.note_test(&node.discriminant);
        walk_switch_statement(self, node);
    }
}

impl<'a> Visit<'a> for NullAccessCollector {
    fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
        let base = member_object(member);
        if !member_optional(member) {
            let kind = match unparenthesized(base) {
                Expression::NullLiteral(_) => Some("null"),
                Expression::Identifier(identifier)
                    if !self.undefined_shadowed && identifier.name == "undefined" =>
                {
                    Some("undefined")
                }
                _ => None,
            };
            if let Some(kind) = kind {
                self.sites.push((kind, base.span()));
            }
        }
        walk_member_expression(self, member);
    }
}

impl<'a> LetToConstCollector<'a> {
    fn note_for_head(&mut self, left: &ForStatementLeft<'a>) {
        if let ForStatementLeft::VariableDeclaration(declaration) = left {
            for declarator in &declaration.declarations {
                if let BindingPattern::BindingIdentifier(identifier) = &declarator.id {
                    self.excluded.insert(identifier.span.start);
                }
            }
        }
    }
}

impl<'a> Visit<'a> for LetToConstCollector<'a> {
    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'a>) {
        let saved = self.in_let;
        self.in_let = declaration.kind == VariableDeclarationKind::Let;
        walk_variable_declaration(self, declaration);
        self.in_let = saved;
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if self.in_let
            && !self.in_export
            && declarator.init.is_some()
            && let BindingPattern::BindingIdentifier(identifier) = &declarator.id
        {
            self.candidates
                .push((identifier.name.as_str(), identifier.span));
        }
        walk_variable_declarator(self, declarator);
    }

    fn visit_for_of_statement(&mut self, node: &ForOfStatement<'a>) {
        self.note_for_head(&node.left);
        walk_for_of_statement(self, node);
    }

    fn visit_for_in_statement(&mut self, node: &ForInStatement<'a>) {
        self.note_for_head(&node.left);
        walk_for_in_statement(self, node);
    }

    fn visit_export_declaration(&mut self, declaration: &ExportDeclaration<'a>) {
        let saved = self.in_export;
        self.in_export = true;
        if let Declaration::VariableDeclaration(inner) = &declaration.declaration {
            for declarator in &inner.declarations {
                if let BindingPattern::BindingIdentifier(identifier) = &declarator.id {
                    self.exported.insert(identifier.span.start);
                }
            }
        }
        walk_declaration(self, &declaration.declaration);
        self.in_export = saved;
    }
}

impl<'p> Visit<'p> for SqlInjectionCollector {
    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        if let Some(name) = callee_member_name(call)
            && SQL_SINK_METHODS.contains(&name)
            && let Some(argument) = call.arguments.first()
            && let Some(expression) = argument.as_expression()
            && is_dynamic_sql(unparenthesized(expression))
        {
            self.sites.push(expression.span());
        }
        walk_call_expression(self, call);
    }
}

impl<'p> Visit<'p> for UselessCollectionCollector<'p> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'p>) {
        if let (BindingPattern::BindingIdentifier(identifier), Some(init)) =
            (&declarator.id, declarator.init.as_ref())
            && is_empty_collection_init(init)
        {
            self.candidates
                .push((identifier.name.as_str(), identifier.span));
        }
        walk_variable_declarator(self, declarator);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        if let Some(member) = call.callee.as_member_expression()
            && let Some(name) = static_property_name(member)
            && WRITE_ONLY_METHODS.contains(&name)
            && let Expression::Identifier(object) = member_object(member)
        {
            self.write_receivers.insert(object.span().start);
        }
        walk_call_expression(self, call);
    }

    fn visit_identifier_reference(&mut self, reference: &oxc_ast::ast::IdentifierReference<'p>) {
        self.references
            .push((reference.name.as_str(), reference.span));
    }
}

impl<'p> Visit<'p> for InPlaceCaptureCollector<'p> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'p>) {
        if let BindingPattern::BindingIdentifier(target) = &declarator.id
            && let Some(init) = declarator.init.as_ref()
            && let Expression::CallExpression(call) = unparenthesized(init)
            && let Some((base, _, method)) = in_place_array_call(call)
            && base != target.name.as_str()
        {
            self.captures.push((base, method, call.span));
        }
        walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'p>) {
        if assign.operator == AssignmentOperator::Assign
            && let Some((target_name, _)) = tb_assignment_target(&assign.left)
            && let Expression::CallExpression(call) = unparenthesized(&assign.right)
            && let Some((base, _, method)) = in_place_array_call(call)
            && base != target_name
        {
            self.captures.push((base, method, call.span));
        }
        walk_assignment_expression(self, assign);
    }

    fn visit_identifier_reference(&mut self, reference: &oxc_ast::ast::IdentifierReference<'p>) {
        self.references
            .push((reference.name.as_str(), reference.span));
    }
}

impl<'p> MapRoundTripCollector<'p> {
    fn note_get(&mut self, call: &CallExpression<'p>, bound_to: &'p str) {
        if let Some(member) = call.callee.as_member_expression()
            && static_property_name(member) == Some("get")
            && call.arguments.len() == 1
            && let Some(argument) = call.arguments.first()
            && let Some(key) = argument.as_expression()
            && let Expression::Identifier(map) = member_object(member)
        {
            self.gets
                .push((bound_to, map.name.as_str(), key.span(), call.span));
        }
    }
}

impl<'p> Visit<'p> for MapRoundTripCollector<'p> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'p>) {
        if let BindingPattern::BindingIdentifier(identifier) = &declarator.id {
            self.variable_writes
                .push((identifier.name.as_str(), identifier.span));
            if let Some(init) = declarator.init.as_ref()
                && let Expression::CallExpression(call) = unparenthesized(init)
            {
                self.note_get(call, identifier.name.as_str());
            }
        }
        walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'p>) {
        if let Some((name, site)) = tb_assignment_target(&assign.left) {
            self.variable_writes.push((name, site));
            if let Expression::CallExpression(call) = unparenthesized(&assign.right) {
                self.note_get(call, name);
            }
        }
        walk_assignment_expression(self, assign);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        if let Some(member) = call.callee.as_member_expression()
            && let Some(name) = static_property_name(member)
            && let Expression::Identifier(map) = member_object(member)
        {
            let map_name = map.name.as_str();
            if name == "set" && call.arguments.len() == 2 {
                let key = call.arguments.first().and_then(Argument::as_expression);
                let value = call.arguments.last().and_then(Argument::as_expression);
                let value_variable = value.and_then(|value| match unparenthesized(value) {
                    Expression::Identifier(identifier) => Some(identifier.name.as_str()),
                    _ => None,
                });
                if let Some(key) = key {
                    self.sets
                        .push((map_name, key.span(), value_variable, call.span));
                }
            } else if matches!(name, "delete" | "clear") {
                self.mutations.push((map_name, call.span));
            }
        }
        walk_call_expression(self, call);
    }
}

/// Exact u32 for a value the caller has proven integral and within 0..=511.
fn integral_mode(value: f64) -> Option<u32> {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "caller guarantees fract() == 0 and 0.0 <= value <= 511.0"
    )]
    let exact = value as i128;
    u32::try_from(exact).ok()
}
impl<'p> Visit<'p> for PermissiveAccessCollector {
    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        let function_name = callee_member_name(call).or_else(|| callee_name(call));
        if let Some(name) = function_name
            && FS_WRITE_FUNCTIONS.contains(&name)
        {
            for argument in &call.arguments {
                let Some(expression) = argument.as_expression() else {
                    continue;
                };
                if let Expression::NumericLiteral(literal) = unparenthesized(expression)
                    && literal.value.fract() == 0.0
                    && literal.value >= 0.0
                    && literal.value <= 511.0
                    && let Some(mode) = integral_mode(literal.value)
                    && mode & 0o022 != 0
                {
                    self.sites.push((literal.span, "mode"));
                }
            }
            let path = call.arguments.first().and_then(Argument::as_expression);
            if let Some(path_expression) = path
                && tmpdir_path(unparenthesized(path_expression))
                && !has_exclusive_flag(call)
            {
                self.sites.push((path_expression.span(), "tmp"));
            }
        }
        walk_call_expression(self, call);
    }
}

impl<'p> ReadonlyFieldCollector<'p> {
    fn note_this_write(&mut self, name: &'p str, span: Span) {
        self.writes.push((name, span, self.constructor_depth > 0));
    }
}

impl<'p> Visit<'p> for ReadonlyFieldCollector<'p> {
    fn visit_class(&mut self, class: &Class<'p>) {
        let write_start = self.writes.len();
        self.stack.push(Vec::new());
        walk_class(self, class);
        let fields = self.stack.pop().unwrap_or_default();
        let class_writes = &self.writes[write_start..];
        for (field_name, field_span) in fields {
            let field_writes: Vec<_> = class_writes
                .iter()
                .filter(|(name, _, _)| *name == field_name)
                .collect();
            let ctor_only =
                !field_writes.is_empty() && field_writes.iter().all(|(_, _, in_ctor)| *in_ctor);
            if ctor_only {
                self.findings.push(field_span);
            }
        }
        self.writes.truncate(write_start);
    }

    fn visit_property_definition(&mut self, definition: &PropertyDefinition<'p>) {
        if !definition.r#static
            && !definition.readonly
            && !definition.computed
            && definition.value.is_none()
            && let Some(name) = duplicated_key_name(&definition.key)
            && let Some(fields) = self.stack.last_mut()
        {
            fields.push((name, definition.key.span()));
        }
        walk_property_definition(self, definition);
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'p>) {
        let saved = self.constructor_depth;
        if method.kind == MethodDefinitionKind::Constructor {
            self.constructor_depth += 1;
        }
        walk_method_definition(self, method);
        self.constructor_depth = saved;
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'p>) {
        if let Some(member) = this_member_target(&assign.left) {
            self.note_this_write(member.0, member.1);
        }
        walk_assignment_expression(self, assign);
    }

    fn visit_update_expression(&mut self, update: &UpdateExpression<'p>) {
        if let SimpleAssignmentTarget::StaticMemberExpression(member) = &update.argument
            && matches!(&member.object, Expression::ThisExpression(_))
        {
            self.note_this_write(member.property.name.as_str(), member.property.span());
        }
        walk_update_expression(self, update);
    }
}

impl<'p> Visit<'p> for DynamicRegexCollector<'p> {
    fn visit_new_expression(&mut self, new_expression: &NewExpression<'p>) {
        if matches!(&new_expression.callee, Expression::Identifier(callee)
            if callee.name == "RegExp")
            && let Some(argument) = new_expression.arguments.first()
            && let Some(expression) = argument.as_expression()
        {
            match unparenthesized(expression) {
                Expression::Identifier(identifier) => {
                    self.unresolved
                        .push((new_expression.span, identifier.name.as_str()));
                }
                expression if !is_static_regex_source(expression) => {
                    self.sites.push(new_expression.span);
                }
                _ => {}
            }
        }
        walk_new_expression(self, new_expression);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'p>) {
        if let BindingPattern::BindingIdentifier(identifier) = &declarator.id {
            let static_init = declarator
                .init
                .as_ref()
                .is_some_and(|init| is_static_regex_source(unparenthesized(init)));
            if static_init {
                self.static_bindings.insert(identifier.name.as_str());
            } else {
                self.dynamic_bindings.insert(identifier.name.as_str());
            }
        }
        walk_variable_declarator(self, declarator);
    }
}

impl<'p> Visit<'p> for SessionRegenerationCollector {
    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        if callee_member_name(call) == Some("post")
            && expression_root_name(&call.callee) == Some("app")
            && let Some(path) = call.arguments.first().and_then(|a| a.as_expression())
            && is_login_path(unparenthesized(path))
            && let Some(handler) = call.arguments.get(1).and_then(|a| a.as_expression())
        {
            // Handler details need source text; resolved in the rule query.
            self.sites.push(handler.span());
        }
        walk_call_expression(self, call);
    }
}

impl<'p> Visit<'p> for UnstableKeyCollector {
    fn visit_jsx_attribute(&mut self, attribute: &JSXAttribute<'p>) {
        if let JSXAttributeName::Identifier(name) = &attribute.name
            && name.name == "key"
            && let Some(JSXAttributeValue::ExpressionContainer(container)) = &attribute.value
            && let Some(expression) = container.expression.as_expression()
            && let Expression::CallExpression(call) = unparenthesized(expression)
            && unstable_key_call(call)
        {
            self.sites.push(attribute.span);
        }
    }
}

impl<'p> Visit<'p> for PromiseChainCollector {
    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        if let Some(link) = call.callee.as_member_expression()
            && let Expression::CallExpression(receiver) = unparenthesized(member_object(link))
            && let Some(then_member) = receiver.callee.as_member_expression()
            && static_property_name(then_member) == Some("then")
            && then_callback_returns_nothing(receiver)
        {
            self.sites.push(receiver.span());
        }
        walk_call_expression(self, call);
    }
}

impl<'p> Visit<'p> for ShellCommandCollector {
    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        let name = callee_name(call).or_else(|| callee_member_name(call));
        if let Some(name) = name
            && SHELL_EXEC_FUNCTIONS.contains(&name)
            && let Some(command) = call
                .arguments
                .first()
                .and_then(|argument| argument.as_expression())
                .and_then(static_command_text)
        {
            if command.starts_with("curl ")
                && command
                    .split_whitespace()
                    .any(|token| token.starts_with("http://"))
            {
                self.sites.push((call.span, "http"));
            } else if is_unpinned_npm_install(&command) {
                self.sites.push((call.span, "npm"));
            }
        }
        walk_call_expression(self, call);
    }
}
