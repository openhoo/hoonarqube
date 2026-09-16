// Family walker for 'naming'.
use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::{RegexNode, parse_regex, regex_search_parsed};
use crate::support::{
    IssueSink, LineIndex, RuleScope, binding_identifier_name, callee_name, constructor_name,
    member_rooted_at, property_key_name, static_property_name, unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentPattern, AssignmentTarget, BinaryExpression, BinaryOperator,
    BindingIdentifier, CallExpression, Declaration, ExportAllDeclaration,
    ExportDefaultDeclarationKind, ExportFromDeclaration, ExportNamedDeclaration, Expression,
    ExpressionStatement, FormalParameter, ImportDeclaration, ImportExpression, JSXAttribute,
    JSXExpressionContainer, JSXSpreadAttribute, MemberExpression, MethodDefinition,
    MethodDefinitionKind, ModuleExportName, NewExpression, NumericLiteral, ObjectProperty,
    PropertyDefinition, PropertyKey, StringLiteral, TSEnumMember, TSLiteralType, UnaryExpression,
    UnaryOperator, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_assignment_expression, walk_assignment_pattern, walk_binary_expression,
    walk_call_expression, walk_declaration, walk_export_all_declaration,
    walk_export_default_declaration_kind, walk_export_from_declaration,
    walk_export_named_declaration, walk_expression, walk_expression_statement,
    walk_formal_parameter, walk_import_declaration, walk_import_expression, walk_member_expression,
    walk_method_definition, walk_new_expression, walk_object_property, walk_property_definition,
    walk_ts_enum_member, walk_ts_literal_type, walk_unary_expression, walk_variable_declarator,
};
use oxc_span::{GetSpan, Span};
use std::collections::{HashMap, HashSet};

fn check_naming_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut names = NameFormatCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        rules,
        parsed_formats: ParsedNameFormats::new(rules),
    };
    names.visit_program(program);
    let mut magic = MagicNumberCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        exempt: HashSet::new(),
        type_depth: 0,
        negation_depth: 0,
    };
    magic.visit_program(program);
    let mut strings = StringStyleCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        single_quotes: rules.single_quotes,
        duplicate_threshold: rules.duplicate_string_threshold,
        ignored_strings: rules.ignored_strings.clone(),
        suppressed: HashSet::new(),
        string_occurrences: Vec::new(),
    };
    strings.visit_program(program);
    strings.report_duplicates();
    let mut issues = names.sink.issues;
    issues.extend(magic.sink.issues);
    issues.extend(strings.sink.issues);
    issues
}

/// `S1441` (quote style per `singleQuotes`) and `S1192` (duplicated string
/// literals, aggregated after the traversal).
struct StringStyleCollector<'a, 'index> {
    sink: IssueSink<'index>,
    single_quotes: bool,
    duplicate_threshold: usize,
    ignored_strings: Vec<String>,
    /// Literal spans whose usage context the reference rule excludes from
    /// duplication counting (import sources, `require` calls, member
    /// accesses, property keys, bare string statements, TS literal types).
    suppressed: HashSet<(u32, u32)>,
    /// Grouping keys are arena-backed and outlive the traversal.
    string_occurrences: Vec<(&'a str, Span)>,
}

impl<'a> Visit<'a> for StringStyleCollector<'a, '_> {
    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        self.check_quote_style(it);
        self.record_occurrence(it);
    }

    fn visit_jsx_attribute(&mut self, _it: &JSXAttribute<'a>) {
        // JSX attribute strings are exempt from quote-style and
        // duplication checks.
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        // Directive-style bare string statements are excluded.
        self.suppress_expression(&it.expression);
        walk_expression_statement(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        self.suppress_module_source(&it.source);
        walk_import_declaration(self, it);
    }

    fn visit_export_all_declaration(&mut self, it: &ExportAllDeclaration<'a>) {
        self.suppress_module_source(&it.source);
        if let Some(exported) = &it.exported {
            self.suppress_export_name(exported);
        }
        walk_export_all_declaration(self, it);
    }

    fn visit_export_named_declaration(&mut self, it: &ExportNamedDeclaration<'a>) {
        for specifier in &it.specifiers {
            self.suppress_export_name(&specifier.exported);
        }
        walk_export_named_declaration(self, it);
    }

    fn visit_export_from_declaration(&mut self, it: &ExportFromDeclaration<'a>) {
        self.suppress_module_source(&it.source);
        for specifier in &it.specifiers {
            self.suppress_export_name(&specifier.exported);
        }
        walk_export_from_declaration(self, it);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        self.suppress_expression(&it.source);
        walk_import_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // `require('...')` module loads are excluded, like import sources.
        if callee_name(it) == Some("require") {
            for argument in &it.arguments {
                if let Some(expression) = argument.as_expression() {
                    self.suppress_expression(expression);
                }
            }
        }
        walk_call_expression(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        self.suppress_property_key(&it.key);
        walk_object_property(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        match it {
            MemberExpression::ComputedMemberExpression(member) => {
                self.suppress_expression(&member.object);
                self.suppress_expression(&member.expression);
            }
            MemberExpression::StaticMemberExpression(member) => {
                self.suppress_expression(&member.object);
            }
            MemberExpression::PrivateFieldExpression(member) => {
                self.suppress_expression(&member.object);
            }
        }
        walk_member_expression(self, it);
    }

    fn visit_ts_literal_type(&mut self, it: &TSLiteralType<'a>) {
        if let oxc_ast::ast::TSLiteral::StringLiteral(literal) = &it.literal {
            self.suppressed
                .insert((literal.span.start, literal.span.end));
        }
        walk_ts_literal_type(self, it);
    }
}

impl<'a> StringStyleCollector<'a, '_> {
    fn check_quote_style(&mut self, literal: &StringLiteral<'_>) {
        let Some(raw) = literal.raw.as_ref().map(oxc_ast::ast::Str::as_str) else {
            return;
        };
        let Some(delimiter) = raw.chars().next() else {
            return;
        };
        let disallowed = if self.single_quotes { '"' } else { '\'' };
        // `avoidEscape` (the reference default): a string containing the
        // preferred quote character stays silent — switching delimiters
        // would force escaping.
        let preferred_char = if self.single_quotes { '\'' } else { '"' };
        if delimiter != disallowed
            || escapes_delimiter(raw, delimiter)
            || raw.contains(preferred_char)
        {
            return;
        }
        let preferred = if self.single_quotes {
            "single"
        } else {
            "double"
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S1441",
            &format!("Strings must use {preferred}quote."),
            literal.span,
        );
    }

    fn suppress_expression(&mut self, expression: &Expression<'_>) {
        if let Some(span) = string_leaf_span(expression) {
            self.suppressed.insert((span.start, span.end));
        }
    }

    fn suppress_module_source(&mut self, source: &StringLiteral<'_>) {
        self.suppressed.insert((source.span.start, source.span.end));
    }

    fn suppress_property_key(&mut self, key: &PropertyKey<'_>) {
        if let PropertyKey::StringLiteral(literal) = key {
            self.suppressed
                .insert((literal.span.start, literal.span.end));
        }
    }

    fn suppress_export_name(&mut self, name: &ModuleExportName<'_>) {
        if let ModuleExportName::StringLiteral(literal) = name {
            self.suppressed
                .insert((literal.span.start, literal.span.end));
        }
    }

    fn record_occurrence(&mut self, literal: &StringLiteral<'a>) {
        let value = literal.value.as_str();
        if self
            .suppressed
            .contains(&(literal.span.start, literal.span.end))
        {
            return;
        }
        if self.ignored_strings.iter().any(|word| word == value) {
            return;
        }
        let key = value.trim();
        // The reference rule counts a literal only when its trimmed content
        // has at least ten characters and carries a separator: `\w`-only
        // content is identifier-like and never grouped.
        if key.chars().count() < 10 {
            return;
        }
        if key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return;
        }
        self.string_occurrences.push((key, literal.span));
    }

    /// One `S1192` issue per over-duplicated value, anchored at the first
    /// occurrence.
    fn report_duplicates(&mut self) {
        let mut groups: HashMap<&str, Vec<Span>> = HashMap::new();
        for (value, span) in &self.string_occurrences {
            groups.entry(value).or_default().push(*span);
        }
        for spans in groups.into_values() {
            if spans.len() >= self.duplicate_threshold {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1192",
                    &format!(
                        "Define a constant instead of duplicating this literal {} times.",
                        spans.len()
                    ),
                    spans[0],
                );
            }
        }
    }
}

/// `S109`: numeric literals outside the reference rule's authorized contexts.
/// The upstream check folds unary `+`/`-` into the literal and exempts the
/// values `-1`, `0`, `1`, `24`, `60` plus integral powers of two and ten;
/// contextual exemptions (assignments, property values, defaults, enum
/// members, class fields, bitwise operands, `parseInt` radixes, JSX) apply
/// only to the literal a context directly holds.
struct MagicNumberCollector<'index> {
    sink: IssueSink<'index>,
    /// Literal spans whose direct context the reference rule exempts.
    exempt: HashSet<(u32, u32)>,
    /// Inside a TypeScript literal type (`type A = 5`).
    type_depth: u32,
    negation_depth: u32,
}

impl<'a> Visit<'a> for MagicNumberCollector<'_> {
    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        // Any declarator initializer is an authorized context; numbers nested
        // inside a call there stay checked.
        if let Some(init) = &it.init {
            record_exempt_leaf(&mut self.exempt, init);
        }
        walk_variable_declarator(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        // Member-target assignments are authorized; simple `x = 5` targets
        // stay checked, mirroring the reference condition.
        if !matches!(it.left, AssignmentTarget::AssignmentTargetIdentifier(_)) {
            record_exempt_leaf(&mut self.exempt, &it.right);
        }
        walk_assignment_expression(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        record_exempt_key(&mut self.exempt, &it.key);
        record_exempt_leaf(&mut self.exempt, &it.value);
        walk_object_property(self, it);
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
        if let Some(value) = &it.value {
            record_exempt_leaf(&mut self.exempt, value);
        }
        walk_property_definition(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        if let Some(initializer) = &it.initializer {
            record_exempt_leaf(&mut self.exempt, initializer);
        }
        walk_formal_parameter(self, it);
    }

    fn visit_assignment_pattern(&mut self, it: &AssignmentPattern<'a>) {
        // Destructuring defaults.
        record_exempt_leaf(&mut self.exempt, &it.right);
        walk_assignment_pattern(self, it);
    }

    fn visit_ts_enum_member(&mut self, it: &TSEnumMember<'a>) {
        if let Some(initializer) = &it.initializer {
            record_exempt_leaf(&mut self.exempt, initializer);
        }
        walk_ts_enum_member(self, it);
    }

    fn visit_ts_literal_type(&mut self, it: &TSLiteralType<'a>) {
        self.type_depth += 1;
        walk_ts_literal_type(self, it);
        self.type_depth -= 1;
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        if is_bitwise_operator(it.operator) {
            record_exempt_leaf(&mut self.exempt, &it.left);
            record_exempt_leaf(&mut self.exempt, &it.right);
        }
        walk_binary_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // A `parseInt` radix argument is always authorized.
        if (callee_name(it) == Some("parseInt") || is_number_parse_int(it))
            && let Some(radix) = it.arguments.get(1)
            && let Some(expression) = radix.as_expression()
        {
            record_exempt_leaf(&mut self.exempt, expression);
        }
        // `JSON.stringify` with the full three-argument form exempts its
        // arguments.
        if is_three_arg_json_stringify(it) {
            for argument in &it.arguments {
                if let Some(expression) = argument.as_expression() {
                    record_exempt_leaf(&mut self.exempt, expression);
                }
            }
        }
        walk_call_expression(self, it);
    }

    fn visit_jsx_attribute(&mut self, _it: &JSXAttribute<'a>) {
        // Numeric JSX attribute values are exempt from magic-number checks.
    }

    fn visit_jsx_expression_container(&mut self, _it: &JSXExpressionContainer<'a>) {
        // Every descendant of a JSX context is exempt.
    }

    fn visit_jsx_spread_attribute(&mut self, _it: &JSXSpreadAttribute<'a>) {}

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        let negated = matches!(it.operator, UnaryOperator::UnaryNegation);
        self.negation_depth += u32::from(negated);
        walk_unary_expression(self, it);
        self.negation_depth -= u32::from(negated);
    }

    fn visit_numeric_literal(&mut self, it: &NumericLiteral<'a>) {
        if self.type_depth > 0 || self.exempt.contains(&(it.span.start, it.span.end)) {
            return;
        }
        let value = if self.negation_depth % 2 == 1 {
            -it.value
        } else {
            it.value
        };
        if is_authorized_number(value) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S109",
            "This numeric literal should be replaced by a named constant.",
            it.span,
        );
    }
}

/// Span of the numeric literal behind unary `+`/`-` and parenthesized
/// wrappers, matching the reference rule's folded number node.
fn numeric_leaf_span(expression: &Expression<'_>) -> Option<Span> {
    match unparenthesized(expression) {
        Expression::NumericLiteral(literal) => Some(literal.span),
        Expression::UnaryExpression(unary) => {
            if !matches!(
                unary.operator,
                UnaryOperator::UnaryNegation | UnaryOperator::UnaryPlus
            ) {
                return None;
            }
            match unparenthesized(&unary.argument) {
                Expression::NumericLiteral(literal) => Some(literal.span),
                _ => None,
            }
        }
        _ => None,
    }
}

fn record_exempt_leaf(spans: &mut HashSet<(u32, u32)>, expression: &Expression<'_>) {
    if let Some(span) = numeric_leaf_span(expression) {
        spans.insert((span.start, span.end));
    }
}

fn record_exempt_key(spans: &mut HashSet<(u32, u32)>, key: &PropertyKey<'_>) {
    match key {
        PropertyKey::NumericLiteral(literal) => {
            spans.insert((literal.span.start, literal.span.end));
        }
        PropertyKey::UnaryExpression(unary) => {
            if let Expression::NumericLiteral(literal) = unparenthesized(&unary.argument) {
                spans.insert((literal.span.start, literal.span.end));
            }
        }
        _ => {}
    }
}

fn is_bitwise_operator(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::BitwiseAnd
            | BinaryOperator::BitwiseOR
            | BinaryOperator::BitwiseXOR
            | BinaryOperator::ShiftLeft
            | BinaryOperator::ShiftRight
            | BinaryOperator::ShiftRightZeroFill
    )
}

/// Integral powers of `base`, including fractions below one (`0.5`, `0.1`).
fn is_power_of(mut value: f64, base: f64) -> bool {
    if value <= 0.0 || !value.is_finite() {
        return false;
    }
    while value > 1.0 {
        value /= base;
        if value.fract() > 0.0 {
            return false;
        }
    }
    while value < 1.0 {
        value *= base;
        if value.fract() > 0.0 {
            return false;
        }
    }
    (value - 1.0).abs() < f64::EPSILON
}

fn is_authorized_number(value: f64) -> bool {
    if matches!(value, -1.0 | 0.0 | 1.0 | 24.0 | 60.0) {
        return true;
    }
    is_power_of(value, 2.0) || is_power_of(value, 10.0)
}

fn is_number_parse_int(call: &CallExpression<'_>) -> bool {
    call.callee.as_member_expression().is_some_and(|member| {
        member_rooted_at(member, "Number") && static_property_name(member) == Some("parseInt")
    })
}

fn is_three_arg_json_stringify(call: &CallExpression<'_>) -> bool {
    call.arguments.len() >= 3
        && call.callee.as_member_expression().is_some_and(|member| {
            member_rooted_at(member, "JSON") && static_property_name(member) == Some("stringify")
        })
}

/// Span of the string literal behind parenthesized wrappers.
fn string_leaf_span(expression: &Expression<'_>) -> Option<Span> {
    match unparenthesized(expression) {
        Expression::StringLiteral(literal) => Some(literal.span),
        _ => None,
    }
}

// ===== Batch2a: name/format convention rules (S100 S101 S117 S109 S1192 S1441 S2430) =====

/// `S100` (function names), `S101` (class and interface names), `S117`
/// (variable, parameter, and property-key names), and `S2430` (lowercase
/// constructor callees). The first three compare against the catalog
/// `format` regular expressions.
/// The three catalog `format` patterns parsed once per file; parsing them
/// per checked name would dominate the traversal otherwise. A failed parse
/// yields an empty alternative set, matching nothing exactly like the
/// one-shot `regex_search`.
struct ParsedNameFormats {
    functions: Vec<Vec<RegexNode>>,
    classes: Vec<Vec<RegexNode>>,
    variables: Vec<Vec<RegexNode>>,
}

impl ParsedNameFormats {
    fn new(rules: &RuleOptions) -> Self {
        Self {
            functions: parse_regex(&rules.format_functions).unwrap_or_default(),
            classes: parse_regex(&rules.format_classes).unwrap_or_default(),
            variables: parse_regex(&rules.format_variables).unwrap_or_default(),
        }
    }
}

struct NameFormatCollector<'a, 'index> {
    sink: IssueSink<'index>,
    rules: &'a RuleOptions,
    parsed_formats: ParsedNameFormats,
}

impl<'a> Visit<'a> for NameFormatCollector<'a, '_> {
    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        match it {
            Declaration::FunctionDeclaration(function) => {
                self.check_function_name(function.id.as_ref());
            }
            Declaration::ClassDeclaration(class) => {
                self.check_type_name("class", class.id.as_ref());
            }
            Declaration::TSInterfaceDeclaration(interface) => {
                self.check_type_name("interface", Some(&interface.id));
            }
            _ => {}
        }
        walk_declaration(self, it);
    }

    fn visit_export_default_declaration_kind(&mut self, it: &ExportDefaultDeclarationKind<'a>) {
        match it {
            ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                self.check_function_name(function.id.as_ref());
            }
            ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                self.check_type_name("class", class.id.as_ref());
            }
            _ => {}
        }
        walk_export_default_declaration_kind(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        match it {
            Expression::FunctionExpression(function) => {
                self.check_function_name(function.id.as_ref());
            }
            Expression::ClassExpression(class) => {
                self.check_type_name("class", class.id.as_ref());
            }
            _ => {}
        }
        walk_expression(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if !matches!(it.kind, MethodDefinitionKind::Constructor)
            && let Some(name) = property_key_name(&it.key)
        {
            Self::check_name(
                &mut self.sink,
                "S100",
                "function",
                name,
                it.key.span(),
                &self.rules.format_functions,
                &self.parsed_formats.functions,
            );
        }
        walk_method_definition(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(name) = binding_identifier_name(&it.id) {
            Self::check_name(
                &mut self.sink,
                "S117",
                "local variable",
                name,
                it.id.span(),
                &self.rules.format_variables,
                &self.parsed_formats.variables,
            );
        }
        walk_variable_declarator(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        if let Some(name) = binding_identifier_name(&it.pattern) {
            Self::check_name(
                &mut self.sink,
                "S117",
                "parameter",
                name,
                it.pattern.span(),
                &self.rules.format_variables,
                &self.parsed_formats.variables,
            );
        }
        walk_formal_parameter(self, it);
    }

    // Object-literal property keys are out of the reference rule's scope:
    // `S117` covers local variables and parameters only.

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if let Some(name) = constructor_name(it)
            && name.starts_with(|first: char| first.is_ascii_lowercase())
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2430",
                "Rename this constructor to start with an uppercase letter.",
                it.callee.span(),
            );
        }
        walk_new_expression(self, it);
    }

    fn visit_jsx_attribute(&mut self, _it: &JSXAttribute<'a>) {
        // JSX attribute names/values are exempt from naming checks.
    }
}

impl NameFormatCollector<'_, '_> {
    fn check_function_name(&mut self, id: Option<&BindingIdentifier<'_>>) {
        let Some(id) = id else {
            return;
        };
        Self::check_name(
            &mut self.sink,
            "S100",
            "function",
            &id.name,
            id.span,
            &self.rules.format_functions,
            &self.parsed_formats.functions,
        );
    }

    fn check_type_name(&mut self, kind: &str, id: Option<&BindingIdentifier<'_>>) {
        let Some(id) = id else {
            return;
        };
        Self::check_name(
            &mut self.sink,
            "S101",
            kind,
            &id.name,
            id.span,
            &self.rules.format_classes,
            &self.parsed_formats.classes,
        );
    }

    fn check_name(
        sink: &mut IssueSink<'_>,
        rule: &str,
        kind: &str,
        name: &str,
        span: Span,
        format: &str,
        parsed: &[Vec<RegexNode>],
    ) {
        if !regex_search_parsed(parsed, name) {
            sink.emit_span(
                RuleScope::Both,
                rule,
                &match rule {
                    "S100" => format!(
                        "Rename this '{name}' function to match the regular expression '{format}'."
                    ),
                    "S101" => format!(
                        "Rename {kind} \"{name}\" to match the regular expression {format}."
                    ),
                    _ => format!(
                        "Rename this {kind} \"{name}\" to match the regular expression {format}."
                    ),
                },
                span,
            );
        }
    }
}

/// Whether `raw` contains a backslash escaping `delimiter`, which makes a
/// quote-style switch unsafe (`S1441` tolerance).
fn escapes_delimiter(raw: &str, delimiter: char) -> bool {
    let mut chars = raw.chars();
    while let Some(current) = chars.next() {
        if current == '\\' && chars.next() == Some(delimiter) {
            return true;
        }
    }
    false
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_naming_rules(ctx.program, ctx.index, ctx.language, ctx.rules)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn function_class_and_interface_names_follow_catalog_formats() {
        let report = js(
            "function goodName() {}\nfunction BadName() {}\nfunction _underscoreOk() {}\nclass GoodClass {}\nclass badClass {}\n",
        );
        assert_eq!(count_key(&report_keys(&report), "javascript:S100"), 1);
        assert_eq!(count_key(&report_keys(&report), "javascript:S101"), 1);
        let bad_function: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S100")
            .collect();
        assert_eq!(
            bad_function,
            vec![&issue(
                "javascript:S100",
                "Rename this 'BadName' function to match the regular expression '^[_a-z][a-zA-Z0-9]*$'.",
                (2, 9),
                (2, 16),
            )]
        );

        let ts_report = ts("interface goodInterface {}\ninterface GoodInterface {}\n");
        assert_eq!(count_key(&report_keys(&ts_report), "typescript:S101"), 1);
        assert_eq!(count_key(&report_keys(&ts_report), "typescript:S100"), 0);
    }

    #[test]
    fn method_names_are_checked_but_constructors_are_exempt() {
        let rules = RuleOptions {
            format_functions: "^doRe$".to_string(),
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules("class C { constructor() {} doIt() {} doRe() {} }\n", &rules);
        assert_eq!(count_key(&flagged, "javascript:S100"), 1);
    }

    #[test]
    fn variables_parameters_and_properties_honor_format() {
        let defaults_clean = js_keys(
            "function f(goodParam) { let goodVar = 1; const UPPER_SNAKE = 2; const opts = { anyKey: 3 }; }\n",
        );
        assert_eq!(count_key(&defaults_clean, "javascript:S117"), 0);

        let rules = RuleOptions {
            format_variables: "^[a-z][a-zA-Z0-9]*$".to_string(),
            ..RuleOptions::default()
        };
        let strict = keys_with_rules(
            "function f(BadParam) { let BadVar = 1; let okVar = 2; }\n",
            &rules,
        );
        assert_eq!(count_key(&strict, "javascript:S117"), 2);
    }

    #[test]
    fn magic_numbers_flagged_only_outside_allowed_contexts() {
        // Assignments, defaults, whitelisted values, and powers of two or ten
        // are exempt; call arguments, comparisons, array elements, and simple
        // `x = 45` assignments stay checked.
        let report = js(
            "const LIMIT = 42;\nlet retries = 3;\nitems[0] = LIMIT;\nfunction g(x = 1, y = 5) { return x; }\nfunction h(z = -1) { return z; }\nlet offset = -7;\ng(2);\n",
        );
        assert_eq!(count_key(&report_keys(&report), "javascript:S109"), 0);

        let flagged = js("g(45);\ncounter = 45;\nif (n > 45) {}\n");
        let magic: Vec<_> = flagged
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S109")
            .collect();
        let message = "This numeric literal should be replaced by a named constant.";
        assert_eq!(
            magic,
            vec![
                &issue("javascript:S109", message, (1, 2), (1, 4)),
                &issue("javascript:S109", message, (2, 10), (2, 12)),
                &issue("javascript:S109", message, (3, 8), (3, 10)),
            ]
        );
    }

    #[test]
    fn magic_number_context_exemptions_follow_the_reference_rule() {
        let clean = js(
            "obj.count = 45;\nconst conf = { width: 45, 45: 'x' };\nclass Box { pad = 45; }\nfunction k(a = 45) {}\nconst { extra = 45 } = box;\nconst radix = parseInt(text, 8);\nconst masked = flag | 45;\n",
        );
        assert_eq!(count_key(&report_keys(&clean), "javascript:S109"), 0);

        let typescript = ts("enum Level { Base = 45 }\ntype Retry = 45;\n");
        assert_eq!(count_key(&report_keys(&typescript), "typescript:S109"), 0);
    }

    #[test]
    fn duplicate_string_literals_report_once_at_first_occurrence() {
        let report = js(
            "log('application/json');\nlog('application/json');\nlog('application/json');\nwarn('lorem ipsum');\nwarn('lorem ipsum');\nwarn('lorem ipsum');\ntag('dup');\ntag('dup');\n",
        );
        let duplicates: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1192")
            .collect();
        // The configured `ignoreStrings` entry never fires; short literals are
        // excluded; the threshold counts the first three occurrences.
        assert_eq!(
            duplicates,
            vec![&issue(
                "javascript:S1192",
                "Define a constant instead of duplicating this literal 3 times.",
                (4, 5),
                (4, 18),
            )]
        );

        let eager = RuleOptions {
            duplicate_string_threshold: 2,
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules(
            "a('lorem ipsum');\nb('lorem ipsum');\nc('other text');\n",
            &eager,
        );
        assert_eq!(count_key(&flagged, "javascript:S1192"), 1);
    }

    #[test]
    fn s1192_excludes_identifier_like_and_structural_contexts() {
        // `require` sources, computed member accesses, property keys, and
        // word-only content never form duplication groups.
        let excluded = js(
            "const a = require('lorem ipsum');\nconst b = require('lorem ipsum');\nconst c = require('lorem ipsum');\n",
        );
        assert_eq!(count_key(&report_keys(&excluded), "javascript:S1192"), 0);

        let member =
            js("headers['lorem ipsum'];\nheaders['lorem ipsum'];\nheaders['lorem ipsum'];\n");
        assert_eq!(count_key(&report_keys(&member), "javascript:S1192"), 0);

        let key = js(
            "const a = { 'lorem ipsum': 1 };\nconst b = { 'lorem ipsum': 2 };\nconst c = { 'lorem ipsum': 3 };\n",
        );
        assert_eq!(count_key(&report_keys(&key), "javascript:S1192"), 0);

        let word_only = js("check('loremipsum');\ncheck('loremipsum');\ncheck('loremipsum');\n");
        assert_eq!(count_key(&report_keys(&word_only), "javascript:S1192"), 0);

        let literal_type =
            ts("type A = 'lorem ipsum';\ntype B = 'lorem ipsum';\ntype C = 'lorem ipsum';\n");
        assert_eq!(
            count_key(&report_keys(&literal_type), "typescript:S1192"),
            0
        );
    }

    #[test]
    fn string_quote_style_follows_single_quotes_param() {
        let report = js(
            "const a = \"double\";\nconst b = 'single';\nconst c = \"escaped \\\"quote\\\"\";\nconst d = `template`;\n",
        );
        let quotes: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1441")
            .collect();
        assert_eq!(
            quotes,
            vec![&issue(
                "javascript:S1441",
                "Strings must use singlequote.",
                (1, 10),
                (1, 18),
            )]
        );

        let double = RuleOptions {
            single_quotes: false,
            ..RuleOptions::default()
        };
        let relaxed = keys_with_rules("const a = 'quoted';\nconst b = \"doubled\";\n", &double);
        assert_eq!(count_key(&relaxed, "javascript:S1441"), 1);
    }

    #[test]
    fn lowercase_constructor_callees_flagged() {
        let report = js("new foo();\nnew Foo();\nnew lib.Bar();\n");
        let constructors: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S2430")
            .collect();
        assert_eq!(
            constructors,
            vec![&issue(
                "javascript:S2430",
                "Rename this constructor to start with an uppercase letter.",
                (1, 4),
                (1, 7),
            )]
        );
    }
    #[test]
    fn naming_compliant_fixture_emits_none_of_the_family_keys() {
        let source = "\
function goodName(paramOne) {
  const localValue = paramOne;
  return localValue;
}

class GoodClass {
  goodMethod() {
    return goodName('once');
  }
}

const item = new GoodClass();
log(item);
";
        let flagged = js_keys(source);
        for key in ["S100", "S101", "S109", "S117", "S1192", "S1441", "S2430"] {
            assert_eq!(
                count_key(&flagged, &format!("javascript:{key}")),
                0,
                "unexpected {key}"
            );
        }
    }

    #[test]
    fn s101_interface_flavor_positive_with_explicit_clean_shapes() {
        let report = js("class lowercase {}\nclass Proper {}\n");
        assert_eq!(count_key(&report_keys(&report), "javascript:S101"), 1);

        let typescript = ts_keys("interface BadName {}\ninterface fine {}\n");
        assert_eq!(count_key(&typescript, "typescript:S101"), 1);
        assert_eq!(count_key(&typescript, "typescript:S100"), 0);
    }

    #[test]
    fn s1192_configured_ignore_strings_never_fire() {
        let rules = RuleOptions {
            ignored_strings: vec!["lorem ipsum".to_string()],
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules(
            "a('lorem ipsum');\nb('lorem ipsum');\nc('lorem ipsum');\n",
            &rules,
        );
        assert_eq!(count_key(&flagged, "javascript:S1192"), 0);
    }

    #[test]
    fn s109_numbers_inside_strings_pass_and_s1441_templates_pass() {
        let report = js("const msg = 'retry 42 times';\nconst keep = `raw ${msg}`;\n");
        assert_eq!(count_key(&report_keys(&report), "javascript:S109"), 0);
        assert_eq!(count_key(&report_keys(&report), "javascript:S1441"), 0);
    }

    #[test]
    fn s2430_uppercase_constructors_pass_explicitly() {
        let clean = js_keys("new Upper();\nnew lib.Bar();\n");
        assert_eq!(count_key(&clean, "javascript:S2430"), 0);
    }

    #[test]
    fn s117_leaves_object_literal_property_keys_unchecked() {
        // Regression of #508: the reference rule applies the variable-name
        // format to local variables and parameters only; object-literal
        // property keys are out of scope.
        let source = "\
const params = {
    _vs_textDocument: 'doc',
    _vs_position: 0,
    _vs_ch: 'x',
};
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S117"), 0);

        let flagged = ts_keys("const _vs_bad = 1;\nfunction f(_vs_param) {}\n");
        assert_eq!(count_key(&flagged, "typescript:S117"), 2);
    }

    #[test]
    fn s1441_avoid_escape_exempts_strings_containing_the_preferred_quote() {
        // Regression of #502/#551: under single-quote mode a double-quoted
        // string containing a single quote stays silent (the reference
        // `avoidEscape` default); the same holds in double-quote mode.
        let report =
            js("const a = \"'\";\nconst b = \"Don't Show Again\";\nconst c = \"plain\";\n");
        let quotes: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1441")
            .collect();
        assert_eq!(
            quotes,
            vec![&issue(
                "javascript:S1441",
                "Strings must use singlequote.",
                (3, 10),
                (3, 17),
            )]
        );

        // A non-quote escape does not trigger the exemption.
        let escaped = js_keys("const e = \"a\\nb\";\n");
        assert_eq!(count_key(&escaped, "javascript:S1441"), 1);

        let double = RuleOptions {
            single_quotes: false,
            ..RuleOptions::default()
        };
        let relaxed = keys_with_rules(
            "const a = 'has \"double\" inside';\nconst b = 'plain';\n",
            &double,
        );
        assert_eq!(count_key(&relaxed, "javascript:S1441"), 1);
    }
}
