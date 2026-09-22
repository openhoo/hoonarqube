use super::s6523_mixed_optional_chains::{
    call_on_short_circuited_chain, member_access_on_short_circuited_chain, report_mixed_chains,
};
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
    ArrowFunctionExpression, AwaitExpression, BinaryExpression, CallExpression,
    ConditionalExpression, Expression, ExpressionStatement, LogicalExpression, MemberExpression,
    NewExpression, SequenceExpression, TemplateLiteral, ThrowStatement, UnaryExpression,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_await_expression, walk_binary_expression,
    walk_call_expression, walk_conditional_expression, walk_expression_statement,
    walk_logical_expression, walk_member_expression, walk_new_expression, walk_sequence_expression,
    walk_template_literal, walk_throw_statement, walk_unary_expression,
};
use oxc_span::{GetSpan, Span};

/// All Tier-C operator/literal and function-census rules in one traversal.
fn check_tier_c_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut census = FunctionCensus::default();
    census.visit_program(program);
    let mut collector = TierCLiteralCollector {
        sink: tier_c_sink(index, language),
        source: program.source_text,
    };
    collector.visit_program(program);
    let await_issues = await_collector_issues(program, index, language, &census);
    let usage_issues = call_usage_collector_issues(program, index, language, &census);
    let chain_issues = optional_chain_collector_issues(program, index, language);
    let mut class_census = ClassCensus::default();
    class_census.visit_program(program);
    class_census.finalize();
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
fn tier_c_sink<'index>(
    index: &'index LineIndex<'index>,
    language: JstsLanguage,
) -> IssueSink<'index> {
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
        discarded_spans: Vec::new(),
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
    for facts in census
        .functions
        .values()
        .flatten()
        .map(|scoped| &scoped.facts)
    {
        // A declared return type that covers every returned literal kind
        // (`any`, `T | undefined`, or an explicit union naming each kind)
        // makes the returns consistent by contract.
        if facts.return_covers_mixed {
            continue;
        }
        let mut kinds = facts.return_kinds.clone();
        kinds.sort();
        kinds.dedup();
        if kinds.len() > 1 {
            issues.push(span_issue(
                index,
                format!("{}:S3800", language.prefix()),
                "Refactor this function to always return the same type.",
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
    for facts in census
        .functions
        .values()
        .flatten()
        .map(|scoped| &scoped.facts)
    {
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
    /// Spans of calls whose result is discarded by the parent construct,
    /// mirroring the reference's `isReturnValueUsed` exemptions: bare
    /// expression statements, expression-bodied arrows (#823), unary and
    /// `await` operands, `throw` arguments, the right operand of logical
    /// expressions, both branches of a conditional, and every
    /// non-final element of a sequence.
    pub(crate) discarded_spans: Vec<Span>,
}

impl TierCCallUsageCollector<'_, '_> {
    /// Marks calls inside `expression` whose result the parent discards.
    /// Parentheses are transparent; a discarded conditional or sequence
    /// discards its value-producing branches.
    fn mark_discarded(&mut self, expression: &Expression<'_>) {
        match unparenthesized(expression) {
            Expression::CallExpression(call) => self.discarded_spans.push(call.span()),
            Expression::ConditionalExpression(conditional) => {
                self.mark_discarded(&conditional.consequent);
                self.mark_discarded(&conditional.alternate);
            }
            Expression::SequenceExpression(sequence) => {
                for element in &sequence.expressions {
                    self.mark_discarded(element);
                }
            }
            _ => {}
        }
    }
}

impl<'a> Visit<'a> for TierCCallUsageCollector<'_, '_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        self.mark_discarded(&it.expression);
        walk_expression_statement(self, it);
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        // An expression-bodied arrow's implicit return is ignored by the
        // callee contract, so the body never "uses" the call's output.
        if let Some(body) = it.get_expression() {
            self.mark_discarded(body);
        }
        walk_arrow_function_expression(self, it);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.mark_discarded(&it.right);
        walk_logical_expression(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.mark_discarded(&it.consequent);
        self.mark_discarded(&it.alternate);
        walk_conditional_expression(self, it);
    }

    fn visit_sequence_expression(&mut self, it: &SequenceExpression<'a>) {
        for element in it
            .expressions
            .iter()
            .take(it.expressions.len().saturating_sub(1))
        {
            self.mark_discarded(element);
        }
        walk_sequence_expression(self, it);
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        self.mark_discarded(&it.argument);
        walk_unary_expression(self, it);
    }

    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        self.mark_discarded(&it.argument);
        walk_await_expression(self, it);
    }

    fn visit_throw_statement(&mut self, it: &ThrowStatement<'a>) {
        self.mark_discarded(&it.argument);
        walk_throw_statement(self, it);
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
    pub(crate) source: &'index str,
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

/// Tier-C collector for `S6523` (`no-unsafe-optional-chaining`): a plain
/// member, index, or call applied to a value that can be `undefined`
/// because an optional chain inside it short-circuited — the chain was
/// broken by a new expression scope such as parentheses. Continuous
/// chains like `a?.b.c` short-circuit their remaining segments and stay
/// clean (#820).
struct TierCOptionalChainCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Spans of every unsafe access; reduced to the maximal spans once
    /// traversal finishes.
    mixed_chains: Vec<Span>,
}

impl<'a> Visit<'a> for TierCOptionalChainCollector<'_> {
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if member_access_on_short_circuited_chain(it) {
            self.mixed_chains.push(it.span());
        }
        walk_member_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if call_on_short_circuited_chain(&it.callee, it.optional) {
            self.mixed_chains.push(it.span());
        }
        walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if call_on_short_circuited_chain(&it.callee, false) {
            self.mixed_chains.push(it.span());
        }
        walk_new_expression(self, it);
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

        let unicode = "const same = 1\u{00a0}===\u{00a0}'1';\n";
        let report = js(unicode);
        let finding = report
            .issues
            .iter()
            .find(|issue| issue.rule_key.ends_with(":S3403"))
            .expect("strict equality finding");
        let operator = unicode.find("===").expect("operator");
        assert_eq!(
            finding.range.start.column,
            u32::try_from(unicode[..operator].chars().count()).expect("column")
        );
        assert_eq!(finding.range.end.column, finding.range.start.column + 3);
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
        assert_eq!(count_key(&js_keys(violating), "javascript:S3758"), 2);

        let array: &str = "const ordered = [1] >= [2];\n";
        assert_eq!(count_key(&js_keys(array), "javascript:S3758"), 2);

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

        // #541: a non-async local returning a call result is not provably
        // synchronous — `run` forwards the Promise from `x`.
        let promise_forwarding = "function run(command) {\n  return x(command);\n}\nfunction x(command) { return Promise.resolve(command); }\nasync function main() {\n  await run(\"go\");\n  await \"literal\";\n}\nmain();\n";
        assert_eq!(
            count_key(&js_keys(promise_forwarding), "javascript:S4123"),
            1
        );

        // A local whose every valued return is a literal stays flagged.
        let literal_returning =
            "function pick() {\n  return 'a';\n}\nasync function main() {\n  await pick();\n}\n";
        assert_eq!(
            count_key(&js_keys(literal_returning), "javascript:S4123"),
            1
        );

        // A local that never returns normally produces no awaited value.
        let throwing = "function fail() {\n  throw new Error('x');\n}\nasync function main() {\n  await fail();\n}\n";
        assert_eq!(count_key(&js_keys(throwing), "javascript:S4123"), 0);

        // An ambient declaration typed `Promise<...>` is awaitable even
        // without the `async` keyword.
        let ambient_promise = "declare function load(): Promise<void>;\nasync function main() {\n  await load();\n}\n";
        assert_eq!(count_key(&ts_keys(ambient_promise), "typescript:S4123"), 0);
    }

    #[test]
    fn nonliteral_valued_returns_are_not_classified_as_void() {
        let source = "function compute() { return makeValue(); }\nconst value = compute();\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S3699"), 0);

        let arrow = "const compute = () => makeValue();\nconst value = compute();\n";
        assert_eq!(count_key(&js_keys(arrow), "javascript:S3699"), 0);
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

        // #534: a declared `T | undefined` return covers both the `T` and
        // the `undefined` returns, so the kinds are consistent.
        let union_return = "interface Entries { files: string[] }\ndeclare function getNode(name: string): { type: string } | undefined;\nfunction getAccessibleEntries(directoryName: string): Entries | undefined {\n  const node = getNode(directoryName);\n  if (!node || node.type !== \"directory\") {\n    return undefined;\n  }\n  return { files: [] };\n}\nexport { getAccessibleEntries };\n";
        assert_eq!(count_key(&ts_keys(union_return), "typescript:S3800"), 0);

        // A declared `any` return also covers mixed literal kinds.
        let any_return = "function pick(flag: boolean): any {\n  if (flag) {\n    return 'yes';\n  }\n  return 0;\n}\n";
        assert_eq!(count_key(&ts_keys(any_return), "typescript:S3800"), 0);

        // `Promise<T | undefined>` covers the awaited mixed kinds too.
        let promise_union = "async function pick(flag: boolean): Promise<string | undefined> {\n  if (flag) {\n    return 'yes';\n  }\n  return undefined;\n}\n";
        assert_eq!(count_key(&ts_keys(promise_union), "typescript:S3800"), 0);

        // Mixed kinds without a covering annotation still flag in TS.
        assert_eq!(count_key(&ts_keys(mixed), "typescript:S3800"), 1);

        // #806: an explicit union that names every returned literal kind
        // covers the mixed returns, even without `undefined` in it.
        let union_literals = "export function selectConstraint(\n  enabled: boolean,\n  useDefault: boolean,\n): false | true | { id: string } {\n  if (!enabled) return false;\n  if (useDefault) return true;\n  return { id: \"custom\" };\n}\n";
        assert_eq!(count_key(&ts_keys(union_literals), "typescript:S3800"), 0);

        let union_object_null = "export function firstValue(\n  entries: Record<string, string>,\n): { key: string; value: string } | null {\n  for (const [key, value] of Object.entries(entries)) {\n    if (value) return { key, value };\n  }\n  return null;\n}\n";
        assert_eq!(
            count_key(&ts_keys(union_object_null), "typescript:S3800"),
            0
        );

        // Primitive unions cover their literal kinds too.
        let primitive_union = "function pick(flag: boolean): string | number {\n  if (flag) {\n    return 'yes';\n  }\n  return 0;\n}\n";
        assert_eq!(count_key(&ts_keys(primitive_union), "typescript:S3800"), 0);

        // Boundary: an annotation that does not cover a returned kind keeps
        // the finding.
        let uncovered = "function pick(flag: boolean): string | number {\n  if (flag) {\n    return 'yes';\n  }\n  return {};\n}\n";
        assert_eq!(count_key(&ts_keys(uncovered), "typescript:S3800"), 1);

        // Boundary: a single non-union annotation does not cover other kinds.
        let single_annotation = "function pick(flag: boolean): string {\n  if (flag) {\n    return 'yes';\n  }\n  return 0;\n}\n";
        assert_eq!(
            count_key(&ts_keys(single_annotation), "typescript:S3800"),
            1
        );
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

        // #524: `return fail()` where `fail` is declared `: never` is the
        // idiomatic never-returning pattern, not a void-result use.
        let never_declared = "declare function fail(message: string): never;\nfunction assertNever(member: never): never {\n  return fail(`Illegal value: ${member}`);\n}\nexport { assertNever };\n";
        assert_eq!(count_key(&ts_keys(never_declared), "typescript:S3699"), 0);

        // A function whose body unconditionally throws never produces a
        // value either, so `return fail()` stays silent in JS too.
        let throwing = "function fail() {\n  throw new Error('x');\n}\nfunction main() {\n  return fail();\n}\n";
        assert_eq!(count_key(&js_keys(throwing), "javascript:S3699"), 0);

        // An ambient declaration with a non-void return type produces a
        // value even though it has no body.
        let ambient_valued = "declare function getNode(name: string): { type: string } | undefined;\nconst node = getNode('x');\n";
        assert_eq!(count_key(&ts_keys(ambient_valued), "typescript:S3699"), 0);
        assert_eq!(count_key(&js_keys(ASYNC_FN), "javascript:S3699"), 0);
    }

    #[test]
    fn expression_bodied_callbacks_do_not_use_void_results() {
        // #823: an expression-bodied arrow's implicit return is ignored
        // by the callee contract, so the body never "uses" the output of
        // a void call — matching the reference's ArrowFunctionExpression
        // exemption.
        let listener = js_keys(
            "function cleanup(code) {\n  console.log(code);\n}\nexport function register(emitter) {\n  emitter.once('exit', (code) => cleanup(code));\n}\n",
        );
        assert_eq!(count_key(&listener, "javascript:S3699"), 0);

        let for_each = js_keys(
            "function cleanup(item) {\n  console.log(item);\n}\nexport function drain(items) {\n  items.forEach((item) => cleanup(item));\n}\n",
        );
        assert_eq!(count_key(&for_each, "javascript:S3699"), 0);

        // A ternary in the arrow body is still the arrow's implicit
        // return; neither branch uses the void output.
        let ternary = js_keys(
            "function close() {}\nfunction openAt(index) {}\nexport function handler(open) {\n  register(() => (open ? close() : openAt(0)));\n}\n",
        );
        assert_eq!(count_key(&ternary, "javascript:S3699"), 0);

        // JSX event handlers are expression-bodied callbacks too.
        let jsx = jsx_keys(
            "function close() {}\nfunction openAt(index) {}\nexport const button = (open) => <button onClick={() => (open ? close() : openAt(0))} />;\n",
        );
        assert_eq!(count_key(&jsx, "javascript:S3699"), 0);

        // Block-bodied arrows have no implicit return; a bare call inside
        // was never a use, and `return cleanup()` stays reportable.
        let block = js_keys(
            "function cleanup() {}\nexport function register(emitter) {\n  emitter.once('exit', (code) => {\n    cleanup(code);\n  });\n}\n",
        );
        assert_eq!(count_key(&block, "javascript:S3699"), 0);
        let block_return = js_keys(
            "function cleanup() {}\nexport function register(emitter) {\n  emitter.once('exit', (code) => {\n    return cleanup(code);\n  });\n}\n",
        );
        assert_eq!(count_key(&block_return, "javascript:S3699"), 1);

        // TypeScript shares the census-driven check.
        let ts_listener = ts_keys(
            "function cleanup(code: number): void {\n  console.log(code);\n}\nexport function register(emitter: { once(s: string, f: (c: number) => void): void }) {\n  emitter.once('exit', (code) => cleanup(code));\n}\n",
        );
        assert_eq!(count_key(&ts_listener, "typescript:S3699"), 0);
    }

    #[test]
    fn discarded_positions_do_not_use_void_results() {
        // #823 follow-through: the reference's `isReturnValueUsed` also
        // exempts conditional branches, logical right operands, sequence
        // elements, unary operands, `await` operands, and `throw`
        // arguments — none of them consume the call's output directly.
        let conditional = js_keys(
            "function cleanup() {}\nexport function run(flag) {\n  flag ? cleanup() : cleanup();\n}\n",
        );
        assert_eq!(count_key(&conditional, "javascript:S3699"), 0);

        let logical = js_keys(
            "function cleanup() {}\nexport function run(flag) {\n  flag && cleanup();\n}\n",
        );
        assert_eq!(count_key(&logical, "javascript:S3699"), 0);

        let sequenced =
            js_keys("function cleanup() {}\nexport function run() {\n  start(), cleanup();\n}\n");
        assert_eq!(count_key(&sequenced, "javascript:S3699"), 0);

        // Actual uses remain reportable: assignment, `return`, chaining
        // on the result, and passing the result to another call.
        let assigned = js_keys("function cleanup() {}\nconst x = cleanup();\n");
        assert_eq!(count_key(&assigned, "javascript:S3699"), 1);

        let returned =
            js_keys("function cleanup() {}\nfunction main() {\n  return cleanup();\n}\n");
        assert_eq!(count_key(&returned, "javascript:S3699"), 1);

        let chained = js_keys("function cleanup() {}\nconst n = cleanup().length;\n");
        assert_eq!(count_key(&chained, "javascript:S3699"), 1);

        let argument = js_keys("function cleanup() {}\nconst s = String(cleanup());\n");
        assert_eq!(count_key(&argument, "javascript:S3699"), 1);

        // The left operand of a logical expression is evaluated for its
        // value, so it still counts as a use.
        let logical_left = js_keys("function cleanup() {}\nconst x = cleanup() || fallback;\n");
        assert_eq!(count_key(&logical_left, "javascript:S3699"), 1);
    }

    #[test]
    fn optional_chains_broken_by_a_new_scope_are_flagged() {
        // #820: a continuous chain short-circuits its remaining segments,
        // so `a?.b.c` cannot throw — only chains broken by a new
        // expression scope (parentheses, call results) are unsafe.
        const CLEAN_ALL_OPTIONAL: &str = "const value = a?.b?.c;\n";
        const CLEAN_OPTIONAL_LAST: &str = "const value = a.b.c?.d;\n";
        const CLEAN_CONTINUOUS: &str = "const value = a?.b.c;\nconst deep = a.b?.c.d;\nconst computed = a?.b[0].c;\nconst called = a?.b.c();\n";
        const CLEAN_CALL_RESULT: &str = "const value = foo(a?.b).c;\n";
        const CLEAN_STILL_OPTIONAL: &str = "const value = (a?.b)?.c;\n";
        const CLEAN_FALLBACK: &str = "const value = (a?.b || c).d;\nconst other = (a?.b ?? c).d;\n";
        let violating: &str = "const value = (a?.b).c;\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S6523"), 1);

        let indexed: &str = "const value = (a?.b)[0];\n";
        assert_eq!(count_key(&js_keys(indexed), "javascript:S6523"), 1);

        let invoked: &str = "const value = (a?.b)();\n";
        assert_eq!(count_key(&js_keys(invoked), "javascript:S6523"), 1);

        let constructed: &str = "const value = new (a?.b)();\n";
        assert_eq!(count_key(&js_keys(constructed), "javascript:S6523"), 1);

        let short_circuit: &str = "const value = (a?.b && c).d;\n";
        assert_eq!(count_key(&js_keys(short_circuit), "javascript:S6523"), 1);

        let sequenced: &str = "const value = (x, a?.b).d;\n";
        assert_eq!(count_key(&js_keys(sequenced), "javascript:S6523"), 1);

        assert_eq!(
            count_key(&js_keys(CLEAN_ALL_OPTIONAL), "javascript:S6523"),
            0
        );

        assert_eq!(
            count_key(&js_keys(CLEAN_OPTIONAL_LAST), "javascript:S6523"),
            0
        );

        assert_eq!(count_key(&js_keys(CLEAN_CONTINUOUS), "javascript:S6523"), 0);

        assert_eq!(
            count_key(&js_keys(CLEAN_CALL_RESULT), "javascript:S6523"),
            0
        );

        assert_eq!(
            count_key(&js_keys(CLEAN_STILL_OPTIONAL), "javascript:S6523"),
            0
        );

        assert_eq!(count_key(&js_keys(CLEAN_FALLBACK), "javascript:S6523"), 0);

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
    fn instances_declared_before_their_class_are_still_resolved() {
        let forward = js_keys(
            "function wrap() {\n  const p = new Point();\n  const label = `at ${p}`;\n  return label;\n}\nwrap();\nclass Point {}\n",
        );
        assert_eq!(count_key(&forward, "javascript:S6551"), 1);
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

    #[test]
    fn nested_same_name_function_keeps_outer_binding_facts() {
        // #137: the nested synchronous `load` must not overwrite the async
        // outer `load` in the function census, so `await load()` in `main`
        // stays clean (issue fixture).
        let shadowed = js("async function load() { return 1; }\n\
             function outer() {\n\
               function load() { return 1; }\n\
               return load();\n\
             }\n\
             async function main() { return await load(); }\n\
             main().then(console.log);\n\
             console.log(outer());\n");
        assert_eq!(filtered(&shadowed, "S4123").len(), 0);

        // Control: a call inside the declaring scope still resolves to the
        // nested synchronous binding.
        let inner = js("async function outer() {\n\
               function load() { return 1; }\n\
               return await load();\n\
             }\n\
             outer();\n");
        assert_eq!(filtered(&inner, "S4123").len(), 1);

        // S3699 twin: the top-level call resolves to the outer void
        // handler, not to the valued nested same-name function.
        let voided = js("function handler() { return; }\n\
             function outer() {\n\
               function handler() { return 1; }\n\
               return handler();\n\
             }\n\
             const total = handler();\n\
             console.log(total);\n");
        assert_eq!(filtered(&voided, "S3699").len(), 1);
    }
}
