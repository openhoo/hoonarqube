// Rule module s5906_prefer_specific_assertion (generated).
//
// `javascript:S5906` + `typescript:S5906` — the most specific assertion
// should be used. Reference semantics: the SonarJS original rule
// `prefer-specific-assertions` (S5906) dispatches each comparison-style
// assertion call to a family extractor. This module implements the pinned
// chai BDD family (`getChaiBddSuggestion`'s `getChaiExpectSuggestion`), the
// family exercised by the pinned oracle: every exceljs `*.spec.js` site.
// The jest/vitest, jasmine, cypress, playwright, and `should`/`assert`
// chai styles are reference families outside this oracle-pinned subset and
// stay silent here.
//
// Reported shapes (chain properties may repeat and `.not` toggles negation):
//
// - `expect(a).to.equal(null)` / `.eql(null)` (matchers: `equal`, `equals`,
//   `eq`, `eql`, `eqls`, exactly one argument) suggests
//   `expect(a).to[.not].be.null`;
// - `expect(a).to.equal(undefined)` suggests `expect(a).to[.not].be.undefined`;
// - `expect(a.length).to.equal(n)` suggests
//   `expect(a).to[.not].have.lengthOf(n)`;
// - `expect(a === b).to.equal(true)` (boolean literal argument) rewrites the
//   boolean expression: nullish operands become `be.null`/`be.undefined`,
//   length comparisons become `have.lengthOf`, `===`/`!==` become
//   `.equal(other-side)`, `instanceof` becomes `be.instanceOf`, numeric
//   comparisons become `be.above`/`be.at.least`/`be.below`/`be.at.most`, and
//   trusted-string `.includes(x)` becomes `.include(x)`.
//
// The finding is anchored on the whole `expect(...).to.equal` callee chain
// (the reference reports `node.callee`) with the reference messages
// `Prefer "<assertion>" over this generic assertion; dedicated matchers read
// better and report clearer failures.` and, for length suggestions, `Prefer
// "<assertion>" over this generic assertion for better reporting; it works
// on any object with a numeric length property.`. The library gate is
// approximated syntactically (the reference also accepts a project-level
// chai dependency manifest; the analyzer is per-file). The rule is
// TEST-scoped: only test files (the pinned server's filename-based
// classification) are analyzed.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file, span_text, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{BinaryOperator, CallExpression, Expression};
use oxc_ast_visit::{Visit, walk};
use oxc_span::{GetSpan, Span};

const CHAI_EQUALITY_MATCHERS: [&str; 5] = ["equal", "equals", "eq", "eql", "eqls"];

const GENERIC_MESSAGE: &str = "Prefer \"{assertion}\" over this generic assertion; dedicated matchers read better and report clearer failures.";
const LENGTH_MESSAGE: &str = "Prefer \"{assertion}\" over this generic assertion for better reporting; it works on any object with a numeric length property.";

/// Entry point: `javascript:S5906` + `typescript:S5906`
/// prefer-specific-assertion check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    if !is_test_file(ctx.path) {
        // Scope TEST: the pinned server classifies by filename.
        return Vec::new();
    }
    let mut collector = SpecificAssertionCollector {
        ctx,
        sink: IssueSink {
            index: ctx.index,
            language: ctx.language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(ctx.program);
    collector.sink.issues
}

struct SpecificAssertionCollector<'a, 'index> {
    ctx: &'a AnalysisContext<'a>,
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for SpecificAssertionCollector<'a, '_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(suggestion) = self.chai_bdd_suggestion(call) {
            let message = if suggestion.is_length {
                LENGTH_MESSAGE
            } else {
                GENERIC_MESSAGE
            };
            self.sink.emit_span(
                RuleScope::Both,
                "S5906",
                &message.replace("{assertion}", &suggestion.assertion),
                call.callee.span(),
            );
        }
        walk::walk_call_expression(self, call);
    }
}

struct Suggestion {
    assertion: String,
    is_length: bool,
}

impl<'a> SpecificAssertionCollector<'a, '_> {
    fn text(&self, span: Span) -> String {
        span_text(self.ctx.source, span).to_string()
    }

    /// `getChaiExpectSuggestion`: `expect(a).to.equal(b)` chains.
    fn chai_bdd_suggestion(&self, call: &CallExpression<'a>) -> Option<Suggestion> {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return None;
        };
        if call.arguments.len() != 1
            || !CHAI_EQUALITY_MATCHERS.contains(&member.property.name.as_str())
        {
            return None;
        }
        let chain = self.expect_chain(&member.object)?;
        self.value_suggestion(
            chain.actual,
            call.arguments.first()?.as_expression()?,
            chain.negated,
            &chain.message_arguments,
        )
    }

    /// `getChaiExpectChain`: walk the chain words down to the `expect(...)`
    /// call, toggling negation on `.not`.
    fn expect_chain(&self, mut expression: &'a Expression<'a>) -> Option<ExpectChain<'a>> {
        let mut negated = false;
        loop {
            // The reference's chain walk does not reject optional members.
            match unparenthesized(expression) {
                Expression::StaticMemberExpression(member) => {
                    if member.property.name == "not" {
                        negated = !negated;
                    }
                    expression = &member.object;
                }
                Expression::CallExpression(call) => {
                    let is_expect_call =
                        matches!(&call.callee, Expression::Identifier(id) if id.name == "expect");
                    if !is_expect_call || call.arguments.is_empty() {
                        return None;
                    }
                    let (first, rest) = call.arguments.split_first()?;
                    let actual = first.as_expression()?;
                    let mut message_arguments = String::new();
                    for argument in rest {
                        message_arguments.push_str(", ");
                        message_arguments.push_str(&self.text(argument.span()));
                    }
                    return Some(ExpectChain {
                        actual,
                        negated,
                        message_arguments,
                    });
                }
                _ => return None,
            }
        }
    }

    /// `getChaiValueSuggestion`: nullish, length, then boolean suggestions,
    /// in the reference order.
    fn value_suggestion(
        &self,
        actual: &Expression<'a>,
        expected: &Expression<'a>,
        negated: bool,
        message_arguments: &str,
    ) -> Option<Suggestion> {
        let actual = unparenthesized(actual);
        let expected = unparenthesized(expected);
        let actual_text = self.text(actual.span());
        if let Expression::NullLiteral(_) = expected {
            return Some(Self::not_length(format!(
                "expect({actual_text}{message_arguments}).to{}.be.null",
                negation(!negated)
            )));
        }
        if matches!(expected, Expression::Identifier(id) if id.name == "undefined") {
            return Some(Self::not_length(format!(
                "expect({actual_text}{message_arguments}).to{}.be.undefined",
                negation(!negated)
            )));
        }
        if let Some(object) = length_access_object(actual) {
            let receiver = self.text(object.span());
            return Some(Suggestion {
                assertion: format!(
                    "expect({receiver}{message_arguments}).to{}.have.lengthOf({})",
                    negation(!negated),
                    self.text(expected.span())
                ),
                is_length: true,
            });
        }
        let Expression::BooleanLiteral(boolean) = expected else {
            return None;
        };
        let positive = boolean.value != negated;
        self.boolean_expression_suggestion(actual, positive, message_arguments)
    }

    fn not_length(assertion: String) -> Suggestion {
        Suggestion {
            assertion,
            is_length: false,
        }
    }

    /// `getBooleanExpressionSuggestion` for the chai family.
    fn boolean_expression_suggestion(
        &self,
        actual: &Expression<'a>,
        positive: bool,
        message_arguments: &str,
    ) -> Option<Suggestion> {
        match unparenthesized(actual) {
            Expression::BinaryExpression(binary) => {
                self.binary_expression_suggestion(binary, positive, message_arguments)
            }
            _ => self.includes_suggestion(actual, positive, message_arguments),
        }
    }

    fn binary_expression_suggestion(
        &self,
        binary: &oxc_ast::ast::BinaryExpression<'a>,
        positive: bool,
        message_arguments: &str,
    ) -> Option<Suggestion> {
        let left_text = self.text(unparenthesized(&binary.left).span());
        let right_text = self.text(unparenthesized(&binary.right).span());
        match binary.operator {
            BinaryOperator::StrictEquality | BinaryOperator::StrictInequality => {
                let same = (binary.operator == BinaryOperator::StrictEquality) == positive;
                if let Some(assertion) = self.specific_equality(binary, same, message_arguments) {
                    return Some(assertion);
                }
                Some(Self::not_length(format!(
                    "expect({left_text}{message_arguments}).to{}.equal({right_text})",
                    negation(same)
                )))
            }
            BinaryOperator::Instanceof => Some(Self::not_length(format!(
                "expect({left_text}{message_arguments}).to{}.be.instanceOf({right_text})",
                negation(positive)
            ))),
            BinaryOperator::LessThan
            | BinaryOperator::GreaterThan
            | BinaryOperator::LessEqualThan
            | BinaryOperator::GreaterEqualThan
                if is_numeric_comparison(binary) =>
            {
                let chai = numeric_comparison_chai(binary.operator, positive)?;
                Some(Self::not_length(format!(
                    "expect({left_text}{message_arguments}).to.be.{chai}({right_text})"
                )))
            }
            _ => None,
        }
    }

    /// `buildSpecificEqualitySuggestion`: nullish operands and length
    /// accesses produce dedicated matchers before the plain rewrite.
    fn specific_equality(
        &self,
        binary: &oxc_ast::ast::BinaryExpression<'a>,
        same: bool,
        message_arguments: &str,
    ) -> Option<Suggestion> {
        let nullish_left = nullish_kind(&binary.left);
        let nullish_right = nullish_kind(&binary.right);
        if nullish_left.is_some() || nullish_right.is_some() {
            let (other, kind) = if nullish_left.is_some() {
                (&binary.right, nullish_left?)
            } else {
                (&binary.left, nullish_right?)
            };
            let other_text = self.text(other.span());
            let suffix = match kind {
                Nullish::Null => "be.null",
                Nullish::Undefined => "be.undefined",
            };
            return Some(Self::not_length(format!(
                "expect({other_text}{message_arguments}).to{}.{suffix}",
                negation(same)
            )));
        }
        if let Some(object) = length_access_object(unparenthesized(&binary.left)) {
            return Some(self.length_equality(
                object,
                &self.text(binary.right.span()),
                same,
                message_arguments,
            ));
        }
        if let Some(object) = length_access_object(unparenthesized(&binary.right)) {
            return Some(self.length_equality(
                object,
                &self.text(binary.left.span()),
                same,
                message_arguments,
            ));
        }
        None
    }

    fn length_equality(
        &self,
        object: &Expression<'a>,
        expected: &str,
        same: bool,
        message_arguments: &str,
    ) -> Suggestion {
        Suggestion {
            assertion: format!(
                "expect({}{message_arguments}).to{}.have.lengthOf({expected})",
                self.text(object.span()),
                negation(same)
            ),
            is_length: true,
        }
    }

    /// `getIncludesSuggestion`: trusted-string `.includes(x)` comparisons.
    fn includes_suggestion(
        &self,
        actual: &Expression<'a>,
        positive: bool,
        message_arguments: &str,
    ) -> Option<Suggestion> {
        let Expression::CallExpression(call) = unparenthesized(actual) else {
            return None;
        };
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return None;
        };
        if member.property.name != "includes"
            || call.arguments.len() != 1
            || !is_trusted_string_receiver(&member.object)
        {
            return None;
        }
        let receiver = self.text(unparenthesized(&member.object).span());
        let needle = self.text(call.arguments[0].span());
        Some(Self::not_length(format!(
            "expect({receiver}{message_arguments}).to{}.include({needle})",
            negation(positive)
        )))
    }
}

struct ExpectChain<'a> {
    actual: &'a Expression<'a>,
    negated: bool,
    message_arguments: String,
}

#[derive(Clone, Copy)]
enum Nullish {
    Null,
    Undefined,
}

fn nullish_kind(expression: &Expression<'_>) -> Option<Nullish> {
    match unparenthesized(expression) {
        Expression::NullLiteral(_) => Some(Nullish::Null),
        Expression::Identifier(id) if id.name == "undefined" => Some(Nullish::Undefined),
        _ => None,
    }
}

/// The reference's `negation(positive)`: `.not` when the assertion is
/// negated, empty otherwise.
fn negation(positive: bool) -> &'static str {
    if positive { "" } else { ".not" }
}

/// `isLengthAccess`: `a.length`, non-computed (the reference does not
/// reject optional members).
fn length_access_object<'a>(expression: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    match unparenthesized(expression) {
        Expression::StaticMemberExpression(member) if member.property.name == "length" => {
            Some(&member.object)
        }
        _ => None,
    }
}

/// `isTrustedStringReceiver`: string literal, expression-free template, or
/// an identifier with a string-like name.
fn is_trusted_string_receiver(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::Identifier(id) => string_like_identifier(id.name.as_str()),
        _ => false,
    }
}

/// The reference's `STRING_LIKE_IDENTIFIER` suffix test (`(?:text|string|
/// message|content|html)$`, case-insensitive).
fn string_like_identifier(name: &str) -> bool {
    ["text", "string", "message", "content", "html"]
        .iter()
        .any(|suffix| {
            name.len() >= suffix.len()
                && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        })
}

fn is_numeric_like_operand(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::NumericLiteral(_) | Expression::BigIntLiteral(_) => true,
        Expression::UnaryExpression(unary)
            if matches!(
                unary.operator,
                oxc_ast::ast::UnaryOperator::UnaryPlus | oxc_ast::ast::UnaryOperator::UnaryNegation
            ) =>
        {
            is_numeric_like_operand(&unary.argument)
        }
        Expression::Identifier(id) => numeric_like_identifier(id.name.as_str()),
        Expression::StaticMemberExpression(member) => {
            numeric_like_identifier(member.property.name.as_str())
        }
        _ => false,
    }
}

fn is_non_numeric_operand(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::Identifier(id) => {
            string_like_identifier(id.name.as_str()) || date_like_identifier(id.name.as_str())
        }
        Expression::StaticMemberExpression(member) => {
            string_like_identifier(member.property.name.as_str())
                || date_like_identifier(member.property.name.as_str())
        }
        _ => false,
    }
}

/// The reference's `NUMERIC_IDENTIFIER` suffix test.
fn numeric_like_identifier(name: &str) -> bool {
    [
        "amount", "count", "delta", "depth", "diff", "duration", "elapsed", "height", "index",
        "length", "level", "limit", "number", "price", "score", "size", "total", "width",
    ]
    .iter()
    .any(|suffix| {
        name.len() >= suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    })
}

/// The reference's `DATE_LIKE_IDENTIFIER` suffix test.
fn date_like_identifier(name: &str) -> bool {
    ["date", "time", "timestamp"].iter().any(|suffix| {
        name.len() >= suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    })
}

fn is_numeric_comparison(binary: &oxc_ast::ast::BinaryExpression<'_>) -> bool {
    is_numeric_like_operand(&binary.left)
        && is_numeric_like_operand(&binary.right)
        && !is_non_numeric_operand(&binary.left)
        && !is_non_numeric_operand(&binary.right)
}

/// `getNumericComparison` chai names, with the reference's negation-by-
/// inversion.
fn numeric_comparison_chai(operator: BinaryOperator, positive: bool) -> Option<&'static str> {
    let effective = if positive {
        operator
    } else {
        match operator {
            BinaryOperator::GreaterThan => BinaryOperator::LessEqualThan,
            BinaryOperator::GreaterEqualThan => BinaryOperator::LessThan,
            BinaryOperator::LessThan => BinaryOperator::GreaterEqualThan,
            BinaryOperator::LessEqualThan => BinaryOperator::GreaterThan,
            _ => return None,
        }
    };
    match effective {
        BinaryOperator::GreaterThan => Some("above"),
        BinaryOperator::GreaterEqualThan => Some("at.least"),
        BinaryOperator::LessThan => Some("below"),
        BinaryOperator::LessEqualThan => Some("at.most"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    /// The rule is TEST-scoped, so helpers analyze a `*.spec.js` path like
    /// the pinned exceljs oracle files.
    fn spec(source: &str) -> hoonarqube_ir::FileReport {
        crate::analyze(
            PathBuf::from("spec/integration/workbook.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        )
    }

    fn spec_keys(source: &str) -> Vec<(String, u32)> {
        report_keys(&spec(source))
    }

    #[test]
    fn s5906_flags_pinned_exceljs_chai_equality_forms() {
        // Pinned oracle: exceljs@5bed18b spec/integration/pr/test-pr-1220.spec.js:8
        // `expect(ws).to.not.equal(undefined)` and workbook-xlsx-writer.spec.js:213
        // `expect(ws2.getColumn(4).width).to.equal(undefined)`.
        let source = "\
expect(ws).to.not.equal(undefined);
expect(ws2.getColumn(4).width).to.equal(undefined);
expect(sheet.getCell(6, 1).value).to.equal(null);
expect(copyStyle(null)).to.equal(null);
";
        let findings = spec_keys(source);
        assert_eq!(count_key(&findings, "javascript:S5906"), 4);
        let report = spec(source);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S5906")
            .expect("pinned exceljs assertion must be reported");
        assert_eq!(
            issue.message,
            "Prefer \"expect(ws).to.not.be.undefined\" over this generic assertion; dedicated matchers read better and report clearer failures."
        );
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(issue.range.start.column, 0);
    }

    #[test]
    fn s5906_flags_pinned_length_assertions_with_length_message() {
        // Pinned oracle: exceljs spec/unit/utils/stream-buf.spec.js
        // `expect(sb.length).to.equal(13)` family, 16 length sites.
        let source = "\
expect(sb.length).to.equal(13);
expect(images.length).to.equal(1);
";
        let report = spec(source);
        let issues = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S5906")
            .collect::<Vec<_>>();
        assert_eq!(issues.len(), 2);
        assert_eq!(
            issues[0].message,
            "Prefer \"expect(sb).to.have.lengthOf(13)\" over this generic assertion for better reporting; it works on any object with a numeric length property."
        );
    }

    #[test]
    fn s5906_rewrites_boolean_expression_arguments_like_reference() {
        let source = "\
expect(wb.getWorksheet(1) === sheet).to.equal(true);
expect(copyStyle(undefined) === undefined).to.equal(true);
expect(buf.length === 20).to.equal(true);
expect(text.includes('x')).to.equal(true);
";
        let messages = spec(source)
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S5906")
            .map(|issue| issue.message.clone())
            .collect::<Vec<_>>();
        assert_eq!(messages.len(), 4);
        assert!(
            messages[0].starts_with("Prefer \"expect(wb.getWorksheet(1)).to.equal(sheet)\" "),
            "boolean equality is rewritten, got {}",
            messages[0]
        );
        assert!(
            messages[1].starts_with("Prefer \"expect(copyStyle(undefined)).to.be.undefined\" "),
            "nullish operands get the nullish matcher, got {}",
            messages[1]
        );
        assert!(
            messages[2].starts_with("Prefer \"expect(buf).to.have.lengthOf(20)\" "),
            "length comparisons get the length matcher, got {}",
            messages[2]
        );
        assert!(
            messages[3].starts_with("Prefer \"expect(text).to.include('x')\" "),
            "trusted-string includes gets the containment matcher, got {}",
            messages[3]
        );
    }

    #[test]
    fn s5906_stays_silent_for_non_generic_and_out_of_family_assertions() {
        let silent = "\
expect(value).to.be.undefined;
expect(value).to.be.null;
expect(value).to.equal(sheet);
expect(items).to.have.lengthOf(2);
expect(value).to.equal(true);
expect(value).to.equal(false);
expect(value).to.not.be.ok;
assert.strictEqual(value, null);
";
        assert_eq!(count_key(&spec_keys(silent), "javascript:S5906"), 0);
    }

    #[test]
    fn s5906_stays_silent_outside_test_files_like_reference_test_scope() {
        // The pinned server classifies `*.spec.js` as TEST and reports the
        // TEST-scoped rule only there.
        let source = "expect(ws).to.not.equal(undefined);\n";
        let main_report = crate::analyze(
            PathBuf::from("lib/csv/csv.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&main_report), "javascript:S5906"), 0);
        let test_report = crate::analyze(
            PathBuf::from("spec/integration/pr/test-pr-1220.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&test_report), "javascript:S5906"), 1);
    }

    #[test]
    fn s5906_also_fires_for_typescript_test_files() {
        let source = "expect(ws).to.equal(undefined);\n";
        let report = crate::analyze(
            PathBuf::from("spec/typescript/exceljs.spec.ts"),
            source,
            crate::JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&report), "typescript:S5906"), 1);
    }
}
