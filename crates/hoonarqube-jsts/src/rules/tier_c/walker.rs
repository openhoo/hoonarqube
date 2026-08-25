// Family walker for 'tier_c' (generated).
use super::s6523_mixed_optional_chains::{chain_mixes_optional, report_mixed_chains};
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::engine::scope_model::ClassCensus;
use crate::engine::scope_model::FunctionCensus;
use crate::support::IssueSink;
use crate::support::LineIndex;
use crate::support::span_issue;
use crate::support::unparenthesized;
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AwaitExpression, BinaryExpression, CallExpression, Expression, ExpressionStatement,
    MemberExpression, TemplateLiteral,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_await_expression, walk_binary_expression, walk_call_expression, walk_expression_statement,
    walk_member_expression, walk_template_literal,
};
use oxc_span::{GetSpan, Span};

/// All Tier-C operator/literal and function-census rules in one traversal.
pub(crate) fn check_tier_c_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut census = FunctionCensus::default();
    census.visit_program(program);
    let mut collector = TierCLiteralCollector {
        sink: tier_c_sink(index, language),
    };
    collector.visit_program(program);
    let await_issues = await_collector_issues(program, index, language, &census);
    let usage_issues = call_usage_collector_issues(program, index, language, &census);
    let chain_issues = optional_chain_collector_issues(program, index, language);
    let mut class_census = ClassCensus::default();
    class_census.visit_program(program);
    let coercion_issues = coercion_collector_issues(program, index, language, &class_census);
    collector.sink.issues.extend(await_issues);
    collector.sink.issues.extend(usage_issues);
    collector.sink.issues.extend(coercion_issues);
    collector.sink.issues.extend(chain_issues);
    flag_mixed_return_kinds(&mut collector.sink.issues, index, language, &census);
    flag_behavior_selector_parameters(&mut collector.sink.issues, index, language, &census);
    collector.sink.issues
}

/// Fresh empty sink bound to the analysis location and language.
fn tier_c_sink(index: &LineIndex, language: JstsLanguage) -> IssueSink<'_> {
    IssueSink {
        index,
        language,
        issues: Vec::new(),
    }
}

/// Await-over-non-promise findings, driven by the function census.
fn await_collector_issues(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    census: &FunctionCensus,
) -> Vec<Issue> {
    let mut await_collector = TierCAwaitCollector {
        sink: tier_c_sink(index, language),
        census,
    };
    await_collector.visit_program(program);
    await_collector.sink.issues
}

/// Direct-call suppression and void-result findings from the function
/// census.
fn call_usage_collector_issues(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    census: &FunctionCensus,
) -> Vec<Issue> {
    let mut usage_collector = TierCCallUsageCollector {
        sink: tier_c_sink(index, language),
        census,
        suppress_span: None,
    };
    usage_collector.visit_program(program);
    usage_collector.sink.issues
}

/// Optional-chain findings, including the deferred mixed-chain reports.
fn optional_chain_collector_issues(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut chain_collector = TierCOptionalChainCollector {
        sink: tier_c_sink(index, language),
        mixed_chains: Vec::new(),
    };
    chain_collector.visit_program(program);
    report_mixed_chains(
        &mut chain_collector.sink,
        std::mem::take(&mut chain_collector.mixed_chains),
    );
    chain_collector.sink.issues
}

/// Type-coercion findings against the class hierarchy census.
fn coercion_collector_issues(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    class_census: &ClassCensus,
) -> Vec<Issue> {
    let mut coercion_collector = TierCCoercionCollector {
        sink: tier_c_sink(index, language),
        census: class_census,
    };
    coercion_collector.visit_program(program);
    coercion_collector.sink.issues
}

/// `S3800`: file-local functions whose returns mix literal kinds.
fn flag_mixed_return_kinds(
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    language: JstsLanguage,
    census: &FunctionCensus,
) {
    for facts in census.functions.values() {
        let mut kinds = facts.return_kinds.clone();
        kinds.sort();
        kinds.dedup();
        if kinds.len() > 1 {
            issues.push(span_issue(
                index,
                format!("{}:S3800", language.prefix()),
                "Refactor this function so that it always returns the same type.",
                facts.span,
            ));
        }
    }
}

/// `S2301`: parameters that only select the function's behavior.
fn flag_behavior_selector_parameters(
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    language: JstsLanguage,
    census: &FunctionCensus,
) {
    for facts in census.functions.values() {
        if let Some(span) = facts.selector_span {
            issues.push(span_issue(
                index,
                format!("{}:S2301", language.prefix()),
                "This parameter only selects the behavior of this function; split it instead.",
                span,
            ));
        }
    }
}

/// Tier-C collector for call-usage checks driven by the function census.
pub(crate) struct TierCCallUsageCollector<'census, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) census: &'census FunctionCensus,
    /// Span of the direct call of the enclosing expression statement, whose
    // value legitimately goes unused.
    pub(crate) suppress_span: Option<Span>,
}

impl<'a> Visit<'a> for TierCCallUsageCollector<'_, '_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        let direct_call = match unparenthesized(&it.expression) {
            Expression::CallExpression(call) => Some(call.span()),
            _ => None,
        };
        let saved = self.suppress_span;
        if direct_call.is_some() {
            self.suppress_span = direct_call;
        }
        walk_expression_statement(self, it);
        self.suppress_span = saved;
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_void_result(it);
        walk_call_expression(self, it);
    }
}

/// Tier-C collector for `await` over non-promises.
pub(crate) struct TierCAwaitCollector<'census, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) census: &'census FunctionCensus,
}

impl<'a> Visit<'a> for TierCAwaitCollector<'_, '_> {
    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        self.check_awaited_value(&it.argument);
        walk_await_expression(self, it);
    }
}

/// Tier-C collector for operator/literal findings.
pub(crate) struct TierCLiteralCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for TierCLiteralCollector<'_> {
    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        self.check_string_addition(it);
        self.check_dissimilar_strict_equality(it);
        self.check_in_with_primitive(it);
        self.check_relational_composite_operand(it);
        self.check_arithmetic_non_number(it);
        self.check_nan_fold(it);
        walk_binary_expression(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        self.check_array_string_index(it);
        walk_member_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_nan_parse(it);
        self.check_builtin_signature(it);
        walk_call_expression(self, it);
    }
}

/// Tier-C collector for mixed optional chains (`S6523`): an optional `?.`
/// access followed, toward the result side, by a plain member or index
/// access of the same chain.
pub(crate) struct TierCOptionalChainCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Spans of every analyzed suffix whose optional flags mix; reduced to
    /// the maximal chains once traversal finishes.
    pub(crate) mixed_chains: Vec<Span>,
}

impl<'a> Visit<'a> for TierCOptionalChainCollector<'_> {
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if chain_mixes_optional(it) {
            self.mixed_chains.push(it.span());
        }
        walk_member_expression(self, it);
    }
}

/// Tier-C collector for implicit string coercions (`S6551`): template
/// interpolation or string concatenation over file-local instances whose
/// class declares no `toString` member. Explicit conversions such as
/// `String(x)` are outside this subset.
pub(crate) struct TierCCoercionCollector<'census, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) census: &'census ClassCensus,
}

impl<'a> Visit<'a> for TierCCoercionCollector<'_, '_> {
    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        self.check_template_coercion(it);
        walk_template_literal(self, it);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        self.check_concat_coercion(it);
        walk_binary_expression(self, it);
    }
}

/// Callee name for sink checks: plain identifier or last static member link
/// (`crypto.createHash` -> `createHash`).
pub(crate) fn sink_callee_name<'a>(callee: &'a Expression<'_>) -> Option<&'a str> {
    match callee {
        Expression::Identifier(identifier) => Some(&identifier.name),
        Expression::StaticMemberExpression(member) => Some(&member.property.name),
        _ => None,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_tier_c_rules(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {

    use crate::test_support::*;

    #[test]
    fn strings_and_non_strings_are_not_added() {
        let violating: &str = "const mix = 'value' + 42;\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S3402"), 1);

        let reversed: &str = "const mix = true + 'value';\n";
        assert_eq!(count_key(&js_keys(reversed), "javascript:S3402"), 1);

        let array: &str = "const label = 'items: ' + [1, 2];\n";
        assert_eq!(count_key(&js_keys(array), "javascript:S3402"), 1);

        let clean_concat: &str = "const ok = 'a' + 'b';\n";
        assert_eq!(count_key(&js_keys(clean_concat), "javascript:S3402"), 0);

        let clean_number: &str = "const sum = 1 + 2;\n";
        assert_eq!(count_key(&js_keys(clean_number), "javascript:S3402"), 0);
    }

    #[test]
    fn strict_equality_between_dissimilar_literals_is_flagged() {
        const CLEAN_STRING: &str = "const str = 'a' === 'b';\n";
        const CLEAN_UNKNOWN: &str = "const unknown = input === 'x';\n";
        let violating: &str = "const same = '1' === 1;\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S3403"), 1);

        let inequality: &str = "const diff = true !== 'true';\n";
        assert_eq!(count_key(&js_keys(inequality), "javascript:S3403"), 1);

        let null_undefined: &str = "const never = null === undefined;\n";
        assert_eq!(count_key(&js_keys(null_undefined), "javascript:S3403"), 1);

        assert_eq!(count_key(&js_keys(CLEAN_STRING), "javascript:S3403"), 0);

        assert_eq!(count_key(&js_keys(CLEAN_UNKNOWN), "javascript:S3403"), 0);

        // TypeScript's catalog has no S3403; the JsOnly scope suppresses it.
        assert_eq!(count_key(&ts_keys(violating), "typescript:S3403"), 0);
    }

    #[test]
    fn operations_that_always_yield_nan_are_flagged() {
        const INFINITY_TIMES_ZERO: &str = "const nan = Infinity * 0;\n";
        const PARSE_GARBAGE: &str = "const nan = parseInt('abc');\n";
        const NUMBER_UNDEFINED: &str = "const nan = Number(undefined);\n";
        const CLEAN_RATIO: &str = "const ratio = width / height;\n";
        const CLEAN_PARSE: &str = "const parsed = parseInt('42');\n";
        let zero_division: &str = "const nan = 0 / 0;\n";
        assert_eq!(count_key(&js_keys(zero_division), "javascript:S3757"), 1);

        assert_eq!(
            count_key(&js_keys(INFINITY_TIMES_ZERO), "javascript:S3757"),
            1
        );

        assert_eq!(count_key(&js_keys(PARSE_GARBAGE), "javascript:S3757"), 1);

        assert_eq!(count_key(&js_keys(NUMBER_UNDEFINED), "javascript:S3757"), 1);

        assert_eq!(count_key(&js_keys(CLEAN_RATIO), "javascript:S3757"), 0);

        assert_eq!(count_key(&js_keys(CLEAN_PARSE), "javascript:S3757"), 0);
    }

    #[test]
    fn in_operator_rejects_primitive_right_hand_sides() {
        const CLEAN: &str = "const has = 'length' in [];\n";
        const CLEAN_OBJECT: &str = "const has = 'a' in { a: 1 };\n";
        let violating: &str = "const has = 'length' in 'abc';\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S3785"), 1);

        let number: &str = "const has = 0 in 42;\n";
        assert_eq!(count_key(&js_keys(number), "javascript:S3785"), 1);

        assert_eq!(count_key(&js_keys(CLEAN), "javascript:S3785"), 0);

        assert_eq!(count_key(&js_keys(CLEAN_OBJECT), "javascript:S3785"), 0);
    }

    #[test]
    fn array_indexes_should_be_numeric() {
        const CLEAN_OBJECT: &str = "const value = obj[\"key\"];\n";
        const CLEAN_NUMBER: &str = "const second = [10, 20][1];\n";
        let violating: &str = "const first = 'a,b'.split(',')[\"0\"];\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S3579"), 1);

        let literal: &str = "const second = [10, 20][\"1\"];\n";
        assert_eq!(count_key(&js_keys(literal), "javascript:S3579"), 1);

        assert_eq!(count_key(&js_keys(CLEAN_OBJECT), "javascript:S3579"), 0);

        assert_eq!(count_key(&js_keys(CLEAN_NUMBER), "javascript:S3579"), 0);
    }

    #[test]
    fn relational_comparisons_reject_object_operands() {
        const CLEAN: &str = "const ordered = 'a' < 'b';\n";
        let violating: &str = "const ordered = {} < {};\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S3758"), 1);

        let array: &str = "const ordered = [1] >= [2];\n";
        assert_eq!(count_key(&js_keys(array), "javascript:S3758"), 1);

        assert_eq!(count_key(&js_keys(CLEAN), "javascript:S3758"), 0);
    }

    #[test]
    fn arithmetic_operands_must_be_numbers() {
        const CLEAN_CONCAT: &str = "const ok = 'a' + 'b';\n";
        const CLEAN_SUM: &str = "const ok = 1 + 2;\n";
        let subtract_string: &str = "const nan = '5' - 3;\n";
        assert_eq!(count_key(&js_keys(subtract_string), "javascript:S3760"), 1);

        let boolean_addition: &str = "const sum = true + 1;\n";
        assert_eq!(count_key(&js_keys(boolean_addition), "javascript:S3760"), 1);

        assert_eq!(count_key(&js_keys(CLEAN_CONCAT), "javascript:S3760"), 0);

        assert_eq!(count_key(&js_keys(CLEAN_SUM), "javascript:S3760"), 0);
    }

    #[test]
    fn await_should_only_apply_to_promises() {
        const SYNC_BUILTIN: &str =
            "async function run() { const data = await JSON.parse('{}'); }\n";
        const LOCAL_SYNC: &str = "function compute() {\n  return 1;\n}\nasync function main() {\n  const v = await compute();\n}\n";
        const CLEAN_ASYNC_LOCAL: &str = "async function load() {\n  return fetch(url);\n}\nasync function main() {\n  const r = await load();\n}\n";
        const CLEAN_UNKNOWN: &str = "async function main() {\n  const r = await mystery();\n}\n";
        let literal: &str = "async function run() { const value = await 42; }\n";
        assert_eq!(count_key(&js_keys(literal), "javascript:S4123"), 1);

        assert_eq!(count_key(&js_keys(SYNC_BUILTIN), "javascript:S4123"), 1);

        assert_eq!(count_key(&js_keys(LOCAL_SYNC), "javascript:S4123"), 1);

        assert_eq!(
            count_key(&js_keys(CLEAN_ASYNC_LOCAL), "javascript:S4123"),
            0
        );

        assert_eq!(count_key(&js_keys(CLEAN_UNKNOWN), "javascript:S4123"), 0);
    }

    #[test]
    fn builtin_arguments_match_documented_types() {
        const BAD_RADIX: &str = "const n = parseInt('ff', 'hex');\n";
        const CHARCODE_STRING: &str = "const c = String.fromCharCode('65');\n";
        const CLEAN_RADIX: &str = "const n = parseInt('ff', 16);\n";
        const CLEAN_PARSE: &str = "const n = parseInt('42');\n";
        const CLEAN_CHARCODE: &str = "const c = String.fromCharCode(65);\n";
        const PARSE_OBJECT: &str = "const n = parseInt({});\n";
        assert_eq!(count_key(&js_keys(PARSE_OBJECT), "javascript:S3782"), 1);

        assert_eq!(count_key(&js_keys(BAD_RADIX), "javascript:S3782"), 1);

        assert_eq!(count_key(&js_keys(CHARCODE_STRING), "javascript:S3782"), 1);

        assert_eq!(count_key(&js_keys(CLEAN_RADIX), "javascript:S3782"), 0);

        assert_eq!(count_key(&js_keys(CLEAN_PARSE), "javascript:S3782"), 0);

        assert_eq!(count_key(&js_keys(CLEAN_CHARCODE), "javascript:S3782"), 0);
    }

    #[test]
    fn functions_should_return_one_type() {
        const CONSISTENT: &str = "function pick(flag) {\n  return flag ? 'a' : 'b';\n}\n";
        const VOID_FN: &str = "function run() {\n  doWork();\n}\n";
        let mixed: &str =
            "function pick(flag) {\n  if (flag) {\n    return 'yes';\n  }\n  return 0;\n}\n";
        assert_eq!(count_key(&js_keys(mixed), "javascript:S3800"), 1);

        assert_eq!(count_key(&js_keys(CONSISTENT), "javascript:S3800"), 0);

        assert_eq!(count_key(&js_keys(VOID_FN), "javascript:S3800"), 0);
    }

    #[test]
    fn void_function_results_should_not_be_used() {
        const RETURNED: &str =
            "function run() {\n  doWork();\n}\nfunction main() {\n  return run();\n}\n";
        const BARE: &str = "function run() {\n  doWork();\n}\nrun();\n";
        const ASYNC_FN: &str = "async function load() {}\nconst r = load();\n";
        const USED: &str = "function run() {\n  doWork();\n}\nconst total = run();\n";
        assert_eq!(count_key(&js_keys(USED), "javascript:S3699"), 1);

        assert_eq!(count_key(&js_keys(RETURNED), "javascript:S3699"), 1);

        assert_eq!(count_key(&js_keys(BARE), "javascript:S3699"), 0);

        assert_eq!(count_key(&js_keys(ASYNC_FN), "javascript:S3699"), 0);
    }

    #[test]
    fn mixed_optional_chains_are_flagged() {
        const CLEAN_ALL_OPTIONAL: &str = "const value = a?.b?.c;\n";
        const CLEAN_OPTIONAL_LAST: &str = "const value = a.b.c?.d;\n";
        let violating: &str = "const value = a?.b.c;\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S6523"), 1);

        let deep: &str = "const value = a.b?.c.d;\n";
        assert_eq!(count_key(&js_keys(deep), "javascript:S6523"), 1);

        let computed: &str = "const value = a?.b[0].c;\n";
        assert_eq!(count_key(&js_keys(computed), "javascript:S6523"), 1);

        assert_eq!(
            count_key(&js_keys(CLEAN_ALL_OPTIONAL), "javascript:S6523"),
            0
        );

        assert_eq!(
            count_key(&js_keys(CLEAN_OPTIONAL_LAST), "javascript:S6523"),
            0
        );

        // Both catalog scopes carry S6523.
        assert_eq!(count_key(&ts_keys(violating), "typescript:S6523"), 1);
    }

    #[test]
    fn instances_of_classes_without_to_string_are_flagged_when_coerced() {
        const WITH_TOSTRING: &str = "class Point {\n  toString() {\n    return 'p';\n  }\n}\nconst p = new Point();\nconst label = `at ${p}`;\n";
        const UNRELATED: &str = "class Point {}\nconst label = `at ${other}`;\n";

        let template: &str = "class Point {}\nconst p = new Point();\nconst label = `at ${p}`;\n";
        assert_eq!(count_key(&js_keys(template), "javascript:S6551"), 1);

        let concat: &str = "class Point {}\nconst p = new Point();\nconst label = 'at ' + p;\n";
        assert_eq!(count_key(&js_keys(concat), "javascript:S6551"), 1);

        let concat_left: &str = "class Point {}\nconst p = new Point();\nconst label = p + '!';\n";
        assert_eq!(count_key(&js_keys(concat_left), "javascript:S6551"), 1);

        assert_eq!(count_key(&js_keys(WITH_TOSTRING), "javascript:S6551"), 0);

        assert_eq!(count_key(&js_keys(UNRELATED), "javascript:S6551"), 0);

        // Both catalog scopes carry S6551.
        assert_eq!(count_key(&ts_keys(template), "typescript:S6551"), 1);
    }

    #[test]
    fn selector_parameters_are_flagged_when_driving_branches() {
        const SWITCH_VIOLATION: &str = "function render(type) {\n  switch (type) {\n    case 'a':\n      return 'A';\n    case 'b':\n      return 'B';\n    default:\n      return '?';\n  }\n}\n";
        const COMPARISON_VIOLATION: &str = "function move(mode) {\n  if (mode === 'fast') {\n    return 1;\n  }\n  return mode === 'slow' ? 2 : 0;\n}\n";
        const CLEAN_NON_SELECTOR: &str = "function pick(flag) {\n  switch (flag) {\n    case true:\n      return 'yes';\n    default:\n      return 'no';\n  }\n}\n";
        const CLEAN_UNUSED_SELECTOR: &str = "function describe(kind) {\n  return kind;\n}\n";

        assert_eq!(count_key(&js_keys(SWITCH_VIOLATION), "javascript:S2301"), 1);

        assert_eq!(
            count_key(&js_keys(COMPARISON_VIOLATION), "javascript:S2301"),
            1
        );

        assert_eq!(
            count_key(&js_keys(CLEAN_NON_SELECTOR), "javascript:S2301"),
            0
        );

        assert_eq!(
            count_key(&js_keys(CLEAN_UNUSED_SELECTOR), "javascript:S2301"),
            0
        );

        // Both catalog scopes carry S2301.
        assert_eq!(count_key(&ts_keys(SWITCH_VIOLATION), "typescript:S2301"), 1);
    }
}
