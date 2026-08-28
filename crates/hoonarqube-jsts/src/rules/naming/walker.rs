// Family walker for 'naming' (generated).
use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::{RegexNode, parse_regex, regex_search_parsed};
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
use std::collections::HashMap;

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
struct StringStyleCollector<'a, 'index> {
    sink: IssueSink<'index>,
    single_quotes: bool,
    duplicate_threshold: usize,
    ignored_strings: Vec<String>,
    /// Literal values are arena-backed and outlive the traversal.
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
            &format!("Strings must use {preferred}quote."),
            literal.span,
        );
    }

    fn record_occurrence(&mut self, literal: &StringLiteral<'a>) {
        let value = literal.value.as_str();
        if value.chars().count() < 2 || self.ignored_strings.iter().any(|word| word == value) {
            return;
        }
        self.string_occurrences.push((value, literal.span));
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

/// `S109`: numeric literals outside the catalog-allowed contexts — const
/// initializers, computed array indexes, and `-1..=2` parameter defaults.
struct MagicNumberCollector<'index> {
    sink: IssueSink<'index>,
    const_initializer_depth: u32,
    index_depth: u32,
    default_depth: u32,
    negation_depth: u32,
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

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if !it.computed
            && let Some(name) = property_key_name(&it.key)
        {
            Self::check_name(
                &mut self.sink,
                "S117",
                "property",
                name,
                it.key.span(),
                &self.rules.format_variables,
                &self.parsed_formats.variables,
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
        let report = js(
            "const LIMIT = 42;\nlet retries = 3;\nitems[0] = LIMIT;\nfunction g(x = 1, y = 5) { return x; }\nfunction h(z = -1) { return z; }\nlet offset = -7;\ng(2);\n",
        );
        let magic: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S109")
            .collect();
        let message = "This numeric literal should be replaced by a named constant.";
        assert_eq!(
            magic,
            vec![
                &issue("javascript:S109", message, (2, 14), (2, 15)),
                &issue("javascript:S109", message, (4, 22), (4, 23)),
                &issue("javascript:S109", message, (6, 14), (6, 15)),
                &issue("javascript:S109", message, (7, 2), (7, 3)),
            ]
        );

        // Boundary: `-1..=2` parameter defaults are allowed, larger ones are not.
        let boundary = js("function k(a = 2, b = 3) {}\n");
        assert_eq!(count_key(&report_keys(&boundary), "javascript:S109"), 1);
    }

    #[test]
    fn duplicate_string_literals_report_once_at_first_occurrence() {
        let report = js(
            "log('application/json');\nlog('application/json');\nlog('application/json');\nwarn('dup');\nwarn('dup');\nwarn('dup');\ntag('x');\ntag('x');\n",
        );
        let duplicates: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1192")
            .collect();
        // The configured `ignoreStrings` entry never fires; single-character
        // literals are excluded; the third occurrence reaches the threshold.
        assert_eq!(
            duplicates,
            vec![&issue(
                "javascript:S1192",
                "Define a constant instead of duplicating this literal 3 times.",
                (4, 5),
                (4, 10),
            )]
        );

        let eager = RuleOptions {
            duplicate_string_threshold: 2,
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules("a('aa');\nb('aa');\nc('bb');\n", &eager);
        assert_eq!(count_key(&flagged, "javascript:S1192"), 1);
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
            ignored_strings: vec!["dup".to_string()],
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules("a('dup');\nb('dup');\nc('dup');\n", &rules);
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
}
