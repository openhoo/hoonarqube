// Family walker for 'naming' (generated).
use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::regex_search;
use crate::support::{
    IssueSink, LineIndex, RuleScope, binding_identifier_name, constructor_name, property_key_name,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    BindingIdentifier, Declaration, ExportDefaultDeclarationKind, Expression, FormalParameter,
    JSXAttribute, MemberExpression, MethodDefinition, MethodDefinitionKind, NewExpression,
    NumericLiteral, ObjectProperty, StringLiteral, UnaryExpression, UnaryOperator,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_binding_pattern, walk_declaration, walk_export_default_declaration_kind, walk_expression,
    walk_formal_parameter, walk_member_expression, walk_method_definition, walk_new_expression,
    walk_object_property, walk_unary_expression, walk_variable_declaration,
    walk_variable_declarator,
};
use oxc_span::{GetSpan, Span};

pub(crate) fn check_naming_rules(
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
    };
    names.visit_program(program);
    let mut magic = MagicNumberCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        const_initializer_depth: 0,
        index_depth: 0,
        default_depth: 0,
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
pub(crate) struct StringStyleCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) single_quotes: bool,
    pub(crate) duplicate_threshold: usize,
    pub(crate) ignored_strings: Vec<String>,
    pub(crate) string_occurrences: Vec<(String, Span)>,
}

impl<'a> Visit<'a> for StringStyleCollector<'_> {
    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        self.check_quote_style(it);
        self.record_occurrence(it);
    }

    fn visit_jsx_attribute(&mut self, _it: &JSXAttribute<'a>) {
        // JSX attribute strings are exempt from quote-style and
        // duplication checks.
    }
}

impl StringStyleCollector<'_> {
    pub(crate) fn check_quote_style(&mut self, literal: &StringLiteral<'_>) {
        let Some(raw) = literal.raw.as_ref().map(oxc_ast::ast::Str::as_str) else {
            return;
        };
        let Some(delimiter) = raw.chars().next() else {
            return;
        };
        let disallowed = if self.single_quotes { '"' } else { '\'' };
        if delimiter != disallowed || escapes_delimiter(raw, delimiter) {
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
            &format!("Use {preferred} quotes for this string literal."),
            literal.span,
        );
    }

    pub(crate) fn record_occurrence(&mut self, literal: &StringLiteral<'_>) {
        let value = literal.value.as_str();
        if value.chars().count() < 2 || self.ignored_strings.iter().any(|word| word == value) {
            return;
        }
        self.string_occurrences
            .push((value.to_string(), literal.span));
    }

    /// One `S1192` issue per over-duplicated value, anchored at the first
    /// occurrence.
    pub(crate) fn report_duplicates(&mut self) {
        let mut groups: Vec<(String, Vec<Span>)> = Vec::new();
        for (value, span) in &self.string_occurrences {
            match groups.iter_mut().find(|(known, _)| known == value) {
                Some((_, spans)) => spans.push(*span),
                None => groups.push((value.clone(), vec![*span])),
            }
        }
        for (value, spans) in groups {
            if spans.len() >= self.duplicate_threshold {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1192",
                    &format!(
                        "Define a constant instead of duplicating this literal \
                         \"{value}\" {} times.",
                        spans.len()
                    ),
                    spans[0],
                );
            }
        }
    }
}

/// `S109`: numeric literals outside the catalog-allowed contexts — const
/// initializers, computed array indexes, and `-1..=2` parameter defaults.
pub(crate) struct MagicNumberCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) const_initializer_depth: u32,
    pub(crate) index_depth: u32,
    pub(crate) default_depth: u32,
    pub(crate) negation_depth: u32,
}

impl<'a> Visit<'a> for MagicNumberCollector<'_> {
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        let in_const = matches!(it.kind, VariableDeclarationKind::Const);
        self.const_initializer_depth += u32::from(in_const);
        walk_variable_declaration(self, it);
        self.const_initializer_depth -= u32::from(in_const);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if let MemberExpression::ComputedMemberExpression(member) = it {
            walk_expression(self, &member.object);
            self.index_depth += 1;
            walk_expression(self, &member.expression);
            self.index_depth -= 1;
        } else {
            walk_member_expression(self, it);
        }
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        walk_binding_pattern(self, &it.pattern);
        if let Some(initializer) = &it.initializer {
            self.default_depth += 1;
            walk_expression(self, initializer);
            self.default_depth -= 1;
        }
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        let negated = matches!(it.operator, UnaryOperator::UnaryNegation);
        self.negation_depth += u32::from(negated);
        walk_unary_expression(self, it);
        self.negation_depth -= u32::from(negated);
    }

    fn visit_numeric_literal(&mut self, it: &NumericLiteral<'a>) {
        let value = if self.negation_depth % 2 == 1 {
            -it.value
        } else {
            it.value
        };
        let allowed = self.const_initializer_depth > 0
            || self.index_depth > 0
            || (self.default_depth > 0 && (-2.0..=2.0).contains(&value));
        if !allowed {
            self.sink.emit_span(
                RuleScope::Both,
                "S109",
                "This numeric literal should be replaced by a named constant.",
                it.span,
            );
        }
    }

    fn visit_jsx_attribute(&mut self, _it: &JSXAttribute<'a>) {
        // Numeric JSX attribute values are exempt from magic-number checks.
    }
}

// ===== Batch2a: name/format convention rules (S100 S101 S117 S109 S1192 S1441 S2430) =====

/// `S100` (function names), `S101` (class and interface names), `S117`
/// (variable, parameter, and property-key names), and `S2430` (lowercase
/// constructor callees). The first three compare against the catalog
/// `format` regular expressions.
pub(crate) struct NameFormatCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) rules: &'a RuleOptions,
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
            self.check_name(
                "S100",
                "function",
                name,
                it.key.span(),
                &self.rules.format_functions,
            );
        }
        walk_method_definition(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(name) = binding_identifier_name(&it.id) {
            self.check_name(
                "S117",
                "variable",
                name,
                it.id.span(),
                &self.rules.format_variables,
            );
        }
        walk_variable_declarator(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        if let Some(name) = binding_identifier_name(&it.pattern) {
            self.check_name(
                "S117",
                "parameter",
                name,
                it.pattern.span(),
                &self.rules.format_variables,
            );
        }
        walk_formal_parameter(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if !it.computed
            && let Some(name) = property_key_name(&it.key)
        {
            self.check_name(
                "S117",
                "property",
                name,
                it.key.span(),
                &self.rules.format_variables,
            );
        }
        walk_object_property(self, it);
    }

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
    pub(crate) fn check_function_name(&mut self, id: Option<&BindingIdentifier<'_>>) {
        let Some(id) = id else {
            return;
        };
        self.check_name(
            "S100",
            "function",
            &id.name,
            id.span,
            &self.rules.format_functions,
        );
    }

    pub(crate) fn check_type_name(&mut self, kind: &str, id: Option<&BindingIdentifier<'_>>) {
        let Some(id) = id else {
            return;
        };
        self.check_name("S101", kind, &id.name, id.span, &self.rules.format_classes);
    }

    pub(crate) fn check_name(
        &mut self,
        rule: &str,
        kind: &str,
        name: &str,
        span: Span,
        format: &str,
    ) {
        if !regex_search(format, name) {
            self.sink.emit_span(
                RuleScope::Both,
                rule,
                &format!("Rename this {kind} to match the regular expression '{format}'."),
                span,
            );
        }
    }
}

/// Whether `raw` contains a backslash escaping `delimiter`, which makes a
/// quote-style switch unsafe (`S1441` tolerance).
pub(crate) fn escapes_delimiter(raw: &str, delimiter: char) -> bool {
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
