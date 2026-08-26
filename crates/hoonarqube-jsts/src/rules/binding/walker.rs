// Family walker for 'binding' (generated).
use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::{RegexNode, parse_regex, regex_search_parsed};
use crate::support::{
    IssueSink, LineIndex, RuleScope, binding_identifier_name, module_export_name_name,
    property_key_name, shannon_entropy_per_char, span_text_contains,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AssignmentExpression, BindingPattern, CallExpression, Class, ExportSpecifier, Expression,
    FormalParameter, FunctionBody, ImportSpecifier, MethodDefinition, MethodDefinitionKind,
    ObjectProperty, Statement, TSInterfaceDeclaration, TSSignature, UnaryOperator,
    VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_assignment_expression, walk_call_expression, walk_class, walk_formal_parameter,
    walk_function_body, walk_method_definition, walk_ts_interface_declaration,
    walk_variable_declarator,
};
use oxc_span::{GetSpan, Span};

fn check_binding_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut collector = BindingCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        rules,
        secret_words_parsed: rules
            .secret_words
            .iter()
            .map(|word| parse_regex(word).unwrap_or_default())
            .collect(),
        callback_argument_depth: 0,
        override_depth: 0,
        constructor_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Binding, pattern, class, and interface batch rules in one traversal:
/// `S2137`, `S2138`, `S6645`, `S6650`, `S1527`, `S3799`, `S2094`, `S4023`,
/// `S4124`, `S6647`, `S1186`, `S2068`, and `S6418`.
struct BindingCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    rules: &'a RuleOptions,
    /// Depth inside call arguments; empty functions there are conventional
    /// callbacks and exempt from `S1186`.
    callback_argument_depth: u32,
    /// `S6418` `secretWords` patterns parsed once per file; an entry that
    /// fails to parse matches nothing, like one-shot `regex_search`.
    secret_words_parsed: Vec<Vec<Vec<RegexNode>>>,
    /// Depth inside `override` methods, also exempt from `S1186`.
    override_depth: u32,
    /// Depth inside constructors, whose emptiness is `S6647`'s domain.
    constructor_depth: u32,
}

impl<'a> Visit<'a> for BindingCollector<'a, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.callback_argument_depth += 1;
        walk_call_expression(self, it);
        self.callback_argument_depth -= 1;
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        self.check_binding_name(&it.id, it.span());
        self.check_declarator_init(it);
        self.check_renamed_binding(&it.id);
        self.check_empty_pattern(&it.id);
        self.check_credential_pair(binding_identifier_name(&it.id), it.init.as_ref());
        walk_variable_declarator(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        self.check_binding_name(&it.pattern, it.span());
        self.check_empty_pattern(&it.pattern);
        walk_formal_parameter(self, it);
    }

    fn visit_import_specifier(&mut self, it: &ImportSpecifier<'a>) {
        if let Some(imported) = module_export_name_name(&it.imported)
            && imported == it.local.name.as_str()
            && span_text_contains(self.source, it.span(), " as ")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6650",
                "Remove this redundant renaming.",
                it.span(),
            );
        }
    }

    fn visit_export_specifier(&mut self, it: &ExportSpecifier<'a>) {
        if let (Some(local), Some(exported)) = (
            module_export_name_name(&it.local),
            module_export_name_name(&it.exported),
        ) && local == exported
            && span_text_contains(self.source, it.span(), " as ")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6650",
                "Remove this redundant renaming.",
                it.span(),
            );
        }
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if !it.shorthand
            && let (Some(key), Expression::Identifier(value)) =
                (property_key_name(&it.key), &it.value)
            && key == value.name.as_str()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6650",
                "Remove this redundant renaming.",
                it.span(),
            );
        }
        self.check_credential_pair(property_key_name(&it.key), Some(&it.value));
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let Some(oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(target)) =
            it.left.as_simple_assignment_target()
            && RESERVED_BINDING_NAMES.contains(&target.name.as_ref())
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2137",
                "Do not assign to this reserved global name.",
                target.span(),
            );
        }
        walk_assignment_expression(self, it);
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        if it.body.body.is_empty() {
            self.sink.emit_span(
                RuleScope::Both,
                "S2094",
                "Remove or implement this empty class.",
                it.span(),
            );
        }
        walk_class(self, it);
    }

    fn visit_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'a>) {
        let signatures = &it.body.body;
        if signatures.is_empty() {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4023",
                "Remove this empty interface.",
                it.span(),
            );
        }
        for signature in signatures {
            if matches!(signature, TSSignature::TSConstructSignatureDeclaration(_)) {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S4124",
                    "Declare construct signatures with a type alias instead.",
                    signature.span(),
                );
            }
        }
        walk_ts_interface_declaration(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if it.kind == MethodDefinitionKind::Constructor
            && let Some(body) = &it.value.body
            && body.statements.is_empty()
            && !it
                .value
                .params
                .items
                .iter()
                .any(FormalParameter::has_modifier)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6647",
                "Remove this constructor or add its logic.",
                it.span(),
            );
        }
        if it.r#override {
            self.override_depth += 1;
        }
        let saved_constructor_depth = self.constructor_depth;
        if it.kind == MethodDefinitionKind::Constructor {
            self.constructor_depth += 1;
        }
        walk_method_definition(self, it);
        self.constructor_depth = saved_constructor_depth;
        if it.r#override {
            self.override_depth -= 1;
        }
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.check_empty_function_body(it.statements.as_slice(), it.span());
        walk_function_body(self, it);
    }
}

impl BindingCollector<'_, '_> {
    /// `S2137` bindings and `S1527` future reserved words.
    fn check_binding_name(&mut self, pattern: &BindingPattern<'_>, span: Span) {
        let Some(name) = binding_identifier_name(pattern) else {
            return;
        };
        if RESERVED_BINDING_NAMES.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2137",
                "Do not bind to this reserved global name.",
                span,
            );
        }
        if FUTURE_RESERVED_WORDS.contains(&name) {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S1527",
                &format!("\"{name}\" is a future reserved word; rename this identifier."),
                span,
            );
        }
    }

    /// `S2138` and `S6645`: explicit `undefined` initializers.
    fn check_declarator_init(&mut self, it: &VariableDeclarator<'_>) {
        let initializes_to_undefined = match &it.init {
            Some(Expression::Identifier(identifier)) => identifier.name == "undefined",
            Some(Expression::UnaryExpression(unary)) => unary.operator == UnaryOperator::Void,
            _ => false,
        };
        if initializes_to_undefined {
            self.sink.emit_span(
                RuleScope::Both,
                "S2138",
                "Initialize with a meaningful value instead of \"undefined\".",
                it.init.as_ref().expect("checked above").span(),
            );
        }
        if matches!(&it.init, Some(Expression::Identifier(identifier)) if identifier.name == "undefined")
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S6645",
                "Remove this explicit \"undefined\" initializer.",
                it.init.as_ref().expect("checked above").span(),
            );
        }
    }

    /// `S6650`: `{ a: a }` destructuring renames.
    fn check_renamed_binding(&mut self, pattern: &BindingPattern<'_>) {
        if let BindingPattern::ObjectPattern(object_pattern) = pattern {
            for property in &object_pattern.properties {
                if !property.shorthand
                    && let (Some(key), Some(binding)) = (
                        property_key_name(&property.key),
                        binding_identifier_name(&property.value),
                    )
                    && key == binding
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S6650",
                        "Remove this redundant renaming.",
                        GetSpan::span(&property.key),
                    );
                }
            }
        }
    }

    /// `S3799`: zero-element destructuring patterns.
    fn check_empty_pattern(&mut self, pattern: &BindingPattern<'_>) {
        let is_empty = match pattern {
            BindingPattern::ObjectPattern(object_pattern) => {
                object_pattern.properties.is_empty() && object_pattern.rest.is_none()
            }
            BindingPattern::ArrayPattern(array_pattern) => array_pattern.elements.is_empty(),
            _ => false,
        };
        if is_empty {
            self.sink.emit_span(
                RuleScope::Both,
                "S3799",
                "Remove this empty destructuring pattern.",
                GetSpan::span(pattern),
            );
        }
    }

    /// `S2068` (password words) and `S6418` (high-entropy secrets next to
    /// secret-suggesting names).
    fn check_credential_pair(
        &mut self,
        context_name: Option<&str>,
        value: Option<&Expression<'_>>,
    ) {
        let Some(context_name) = context_name else {
            return;
        };
        let Some(Expression::StringLiteral(literal)) = value else {
            return;
        };
        let text = literal.value.as_str();
        if text.is_empty() {
            return;
        }
        if name_contains_any(context_name, &self.rules.password_words) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2068",
                "Remove this hard-coded credential.",
                literal.span,
            );
        }
        let lowered = context_name.to_lowercase();
        let name_matches_secret_word = self.secret_words_parsed.iter().any(|word| {
            regex_search_parsed(word, context_name) || regex_search_parsed(word, &lowered)
        });
        if name_matches_secret_word
            && text.chars().count() >= 16
            && shannon_entropy_per_char(text) > self.rules.secret_entropy_sensibility
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6418",
                "Remove this hard-coded secret.",
                literal.span,
            );
        }
    }

    /// `S1186`: empty function bodies outside callback conventions.
    fn check_empty_function_body(&mut self, statements: &[Statement<'_>], span: Span) {
        if statements.is_empty()
            && self.callback_argument_depth == 0
            && self.override_depth == 0
            && self.constructor_depth == 0
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1186",
                "Add logic to this empty function or remove it.",
                span,
            );
        }
    }
}

/// ECMAScript 3 future reserved words flagged by `S1527` (JavaScript-only).
const FUTURE_RESERVED_WORDS: [&str; 17] = [
    "abstract",
    "boolean",
    "byte",
    "char",
    "double",
    "final",
    "float",
    "goto",
    "int",
    "long",
    "native",
    "short",
    "synchronized",
    "throws",
    "transient",
    "volatile",
    "enum",
];

/// Names whose binding or assignment `S2137` forbids.
const RESERVED_BINDING_NAMES: [&str; 5] = ["undefined", "NaN", "Infinity", "eval", "arguments"];

/// Whether a binding name matches one of the configured words
/// (case-insensitively).
fn name_contains_any(name: &str, words: &[String]) -> bool {
    let lowered = name.to_lowercase();
    words.iter().any(|word| lowered.contains(word))
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_binding_rules(ctx.program, ctx.source, ctx.index, ctx.language, ctx.rules)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn binding_and_pattern_batch_rules_fire() {
        let source = "\
const shadow = undefined;
const int = 1;
const { renamed: renamed } = pair;
const {} = empty;
const password = 'hunter2';
const apiKeyValue = 'Zx9kQ2vL8pR4tW7yB1nM6cJ3fH5dG0aE#';
NaN = 1;
";
        let flagged = js_keys(source);
        for key in [
            "S2138", "S6645", "S1527", "S6650", "S3799", "S2068", "S6418", "S2137",
        ] {
            assert!(
                count_key(&flagged, &format!("javascript:{key}")) >= 1,
                "expected {key}"
            );
        }
    }

    #[test]
    fn class_interface_and_empty_body_rules_respect_scope() {
        let ts_source = "\
class Empty {}
interface Nothing {}
interface WithCtor { new (): void; }
function bare() {}
const cb = () => {};
arr.map(function () {});
";
        let ts_findings = findings(ts_source, JstsLanguage::TypeScript);
        assert_eq!(count_key(&ts_findings, "typescript:S2094"), 1);
        assert_eq!(count_key(&ts_findings, "typescript:S4023"), 1);
        assert_eq!(count_key(&ts_findings, "typescript:S4124"), 1);
        // Callback conventions suppress `S1186`.
        assert_eq!(count_key(&ts_findings, "typescript:S1186"), 2);

        let js_findings = findings(ts_source, JstsLanguage::JavaScript);
        assert_eq!(count_key(&js_findings, "javascript:S4023"), 0);
        assert_eq!(count_key(&js_findings, "javascript:S4124"), 0);
    }
    #[test]
    fn s6647_flags_empty_constructor_logic_and_param_property_variants() {
        let flagged = js_keys("class C {\n  constructor() {}\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6647"), 1);

        let with_logic = js_keys("class D {\n  constructor() {\n    this.ready = true;\n  }\n}\n");
        assert_eq!(count_key(&with_logic, "javascript:S6647"), 0);

        // A TypeScript parameter property counts as constructor logic.
        let param_property = ts_keys("class E {\n  constructor(private name) {}\n}\n");
        assert_eq!(count_key(&param_property, "typescript:S6647"), 0);
    }

    #[test]
    fn binding_compliant_fixture_emits_none_of_the_family_keys() {
        let source = "\
const first = 1;
let second = null;

function work(value) {
  return value + second;
}

class Model {
  constructor() {
    this.ready = true;
  }

  run() {
    return work(first);
  }
}

export { Model };
";
        let flagged = js_keys(source);
        for key in [
            "S1186", "S1527", "S2068", "S2094", "S2137", "S2138", "S3799", "S4023", "S4124",
            "S6418", "S6645", "S6647", "S6650",
        ] {
            assert_eq!(
                count_key(&flagged, &format!("javascript:{key}")),
                0,
                "unexpected {key}"
            );
        }
    }

    #[test]
    fn s2138_and_s6645_void_zero_and_typescript_scope_edges() {
        let void_init = js_keys("let x = void 0;\n");
        assert_eq!(count_key(&void_init, "javascript:S2138"), 1);
        assert_eq!(count_key(&void_init, "javascript:S6645"), 0);

        let explicit = js_keys("let y = undefined;\n");
        assert_eq!(count_key(&explicit, "javascript:S2138"), 1);
        assert_eq!(count_key(&explicit, "javascript:S6645"), 1);

        let typescript = ts_keys("let z = undefined;\n");
        assert_eq!(count_key(&typescript, "typescript:S2138"), 1);
        assert_eq!(count_key(&typescript, "typescript:S6645"), 0);

        let meaningful = js_keys("let w = null;\n");
        assert_eq!(count_key(&meaningful, "javascript:S2138"), 0);
    }

    #[test]
    fn s2068_and_s6418_credential_boundaries_stay_clean() {
        let boundaries = js_keys(
            "const password = '';\nconst nickname = 'hunter2';\nconst apiKey = 'aaaaaaaaaaaaaaaa';\nconst token = 'Zx9kQ2';\n",
        );
        assert_eq!(count_key(&boundaries, "javascript:S2068"), 0);
        assert_eq!(count_key(&boundaries, "javascript:S6418"), 0);
    }

    #[test]
    fn s6650_flags_import_and_export_renames_aliasing_passes() {
        let import_rename = js_keys("import { alpha as alpha } from 'm';\n");
        assert_eq!(count_key(&import_rename, "javascript:S6650"), 1);

        let export_rename = js_keys("const tool = 1;\nexport { tool as tool };\n");
        assert_eq!(count_key(&export_rename, "javascript:S6650"), 1);

        let plain = js_keys("import { beta } from 'm';\nconst gamma = 2;\nexport { gamma };\n");
        assert_eq!(count_key(&plain, "javascript:S6650"), 0);

        let aliased = js_keys("import { alpha as beta } from 'm';\nconst { a: b } = pair;\n");
        assert_eq!(count_key(&aliased, "javascript:S6650"), 0);
    }

    #[test]
    fn s3799_array_and_parameter_patterns_flagged_nonempty_pass() {
        let array_pattern = js_keys("const [] = list;\n");
        assert_eq!(count_key(&array_pattern, "javascript:S3799"), 1);

        let param_pattern = js_keys("function f({}) {\n  return 1;\n}\n");
        assert_eq!(count_key(&param_pattern, "javascript:S3799"), 1);

        let populated = js_keys("const [head] = list;\nconst { tail } = obj;\n");
        assert_eq!(count_key(&populated, "javascript:S3799"), 0);
    }

    #[test]
    fn s2137_binding_flavor_and_s1527_typescript_scope() {
        let bound = js_keys("let Infinity = 1;\n");
        assert_eq!(count_key(&bound, "javascript:S2137"), 1);
        assert_eq!(count_key(&bound, "javascript:S1527"), 0);

        let assigned = js_keys("eval = 2;\n");
        assert_eq!(count_key(&assigned, "javascript:S2137"), 1);

        let reserved_word = js_keys("let abstract = 3;\n");
        assert_eq!(count_key(&reserved_word, "javascript:S1527"), 1);

        let typescript = ts_keys("let normalName = 4;\n");
        assert_eq!(count_key(&typescript, "typescript:S1527"), 0);
        assert_eq!(count_key(&typescript, "typescript:S2137"), 0);
    }

    #[test]
    fn s2094_s4023_s4124_populated_shapes_pass_construct_signature_flags() {
        let populated_class = js_keys("class Full {\n  run() {\n    return work();\n  }\n}\n");
        assert_eq!(count_key(&populated_class, "javascript:S2094"), 0);

        let typescript =
            ts_keys("interface Rich {\n  width: number;\n}\nclass Impl {\n  width = 1;\n}\n");
        assert_eq!(count_key(&typescript, "typescript:S4023"), 0);
        assert_eq!(count_key(&typescript, "typescript:S4124"), 0);

        let construct_signature = ts_keys("interface Factory {\n  new (): Factory;\n}\n");
        assert_eq!(count_key(&construct_signature, "typescript:S4124"), 1);
        assert_eq!(count_key(&construct_signature, "typescript:S4023"), 0);
    }
}
