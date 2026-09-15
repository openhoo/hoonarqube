// Rule module s5914_trivial_assertions (generated).
//
// `javascript:S5914` + `typescript:S5914` — assertions should not be
// trivially true. Reference semantics: the SonarJS-owned rule
// `no-trivial-assertions` (packages/analysis/src/jsts/rules/S5914),
// reported with scope TEST: only files the analyzer's filename-based
// `is_test_file` classifies as test files are checked.
//
// An assertion extracted by the shared `test_assertions` machinery
// (jest-like/jasmine/playwright `expect`, chai assert/expect/should,
// node:assert) is reported when it is guaranteed to succeed:
//
// - predicate assertions (`assert.ok`, `expect(x).toBeTruthy`, chai
//   `.ok`/`.true`/`.null`/`.exist`, …) whose actual resolves to a
//   constant primitive satisfying the predicate (negation-aware), or
//   whose actual is a freshly-created reference (object/array/function/
//   class/new/regex literals are always truthy, defined, and existing):
//   "Replace this assertion; it always succeeds." for constants and
//   "Replace this assertion; the value is freshly created here, so the
//   result is independent of the code under test." for fresh references;
// - strict comparisons (`toBe`, `assert.strictEqual`, chai `strictEqual`/
//   `.equal`) where either side is a freshly-created reference, reported
//   on that side with "Use `<deep-matcher>` instead; freshly-created
//   values are never identical to other values." regardless of which way
//   the comparison resolves (the toBe/toEqual mixup case);
// - strict or loose comparisons where both sides resolve to constant
//   primitives and the comparison always succeeds (negation-aware):
//   "Replace this assertion; it always succeeds.".
//
// Assertions guaranteed to *fail* are not reported (they self-correct by
// failing the suite), except the fresh-identity case above. Deep-equality
// comparisons are intentionally skipped. The reference offers
// suggestions; no auto-fix is offered here.

use crate::context::AnalysisContext;
use crate::rules::test_assertions::{
    Assertion, AssertionKind, AssertionStyle, Comparison, collect_file_imports,
    extract_test_assertion, fresh_reference_predicate_holds, is_fresh_reference_expression,
    loose_equals, predicate_holds, resolve_constant, strict_equality_holds,
};
use crate::support::{IssueSink, RuleScope, is_test_file};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::Expression;
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};

/// Entry point: `javascript:S5914` + `typescript:S5914`
/// no-trivial-assertions check over the parsed program (test files only).
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if !is_test_file(ctx.path) {
        // Scope TEST: the pinned server classifies by filename.
        return sink.issues;
    }
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    let imports = collect_file_imports(semantic);
    for node in semantic.nodes().iter() {
        if !matches!(
            node.kind(),
            AstKind::CallExpression(_) | AstKind::StaticMemberExpression(_)
        ) {
            continue;
        }
        let Some(assertion) = extract_test_assertion(semantic, node, &imports) else {
            continue;
        };
        check_assertion(&mut sink, semantic, &assertion);
    }
    sink.issues
}

fn check_assertion(sink: &mut IssueSink<'_>, semantic: &Semantic<'_>, assertion: &Assertion<'_>) {
    match assertion.kind {
        AssertionKind::Predicate { predicate, actual } => {
            resolve_predicate(sink, semantic, assertion, predicate, actual);
        }
        AssertionKind::Comparison {
            comparison,
            actual,
            expected,
        } => {
            resolve_comparison(sink, semantic, assertion, comparison, actual, expected);
        }
    }
}

/// Predicate assertion on a constant or freshly-created actual.
fn resolve_predicate(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    assertion: &Assertion<'_>,
    predicate: crate::rules::test_assertions::Predicate,
    actual: &Expression<'_>,
) {
    if let Some(value) = resolve_constant(semantic, actual) {
        if predicate_holds(predicate, &value) != assertion.negated {
            emit(
                sink,
                actual.span(),
                "Replace this assertion; it always succeeds.",
            );
            return;
        }
    }
    if is_fresh_reference_expression(actual)
        && fresh_reference_predicate_holds(predicate) != assertion.negated
    {
        emit(
            sink,
            actual.span(),
            "Replace this assertion; the value is freshly created here, so the result is independent of the code under test.",
        );
    }
}

/// Strict/loose comparison assertions: fresh-identity mixups and
/// constant-vs-constant always-true comparisons.
fn resolve_comparison(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    assertion: &Assertion<'_>,
    comparison: Comparison,
    actual: &Expression<'_>,
    expected: &Expression<'_>,
) {
    if comparison == Comparison::Strict {
        for side in [actual, expected] {
            if is_fresh_reference_expression(side) {
                let matcher = deep_equality_matcher(assertion.style, assertion.negated);
                emit(
                    sink,
                    side.span(),
                    &format!(
                        "Use `{matcher}` instead; freshly-created values are never identical to other values."
                    ),
                );
                return;
            }
        }
    }
    if comparison == Comparison::Deep {
        return;
    }
    let Some(actual_value) = resolve_constant(semantic, actual) else {
        return;
    };
    let Some(expected_value) = resolve_constant(semantic, expected) else {
        return;
    };
    let equal = match comparison {
        Comparison::Strict => {
            strict_equality_holds(assertion.style, &actual_value, &expected_value)
        }
        Comparison::Loose => loose_equals(&actual_value, &expected_value),
        Comparison::Deep => unreachable!("deep comparisons return early"),
    };
    if equal != assertion.negated {
        emit(
            sink,
            actual.span(),
            "Replace this assertion; it always succeeds.",
        );
    }
}

/// `getDeepEqualityMatcher`: the deep-equality matcher for the
/// assertion's own style and negation.
fn deep_equality_matcher(style: AssertionStyle, negated: bool) -> &'static str {
    match style {
        AssertionStyle::JestLike | AssertionStyle::Jasmine | AssertionStyle::Playwright => {
            if negated { "not.toEqual" } else { "toEqual" }
        }
        AssertionStyle::ChaiBdd => {
            if negated { "not.deep.equal" } else { "deep.equal" }
        }
        AssertionStyle::ChaiAssert => {
            if negated { "notDeepEqual" } else { "deepEqual" }
        }
        AssertionStyle::NodeAssert => {
            if negated { "notDeepStrictEqual" } else { "deepStrictEqual" }
        }
    }
}

fn emit(sink: &mut IssueSink<'_>, span: Span, message: &str) {
    sink.emit_span(RuleScope::Both, "S5914", message, span);
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s5914_flags_trivially_true_vitest_assertions() {
        let source = "\
import { expect, test } from 'vitest';

test('checks user state', () => {
  expect(true).toBeTruthy();
  expect(undefined).not.toBeDefined();
  expect([]).toBeTruthy();
  expect(class User {}).toBeTruthy();
  expect(getUser()).toBe({ id: 1 });
  const limit = 10 + 5;
  expect(limit).toBeTruthy();
});
";
        let keys = test_file_keys(source);
        assert_eq!(count_key(&keys, "javascript:S5914"), 6);
    }

    #[test]
    fn s5914_flags_node_assert_and_chai_styles() {
        let source = "\
import assert from 'node:assert';
import { expect as chaiExpect, assert as chaiAssert } from 'chai';

assert.ok('ready');
assert.strictEqual(readConfiguration(), { mode: 'test' });
assert.notStrictEqual(getItems(), []);
const expectedMode = 'test';
assert.strictEqual(expectedMode, 'test');
chaiAssert.isTrue(1 === 1);
chaiExpect(getUser()).to.equal({ id: 1 });
";
        let keys = test_file_keys(source);
        assert_eq!(count_key(&keys, "javascript:S5914"), 6);
    }

    #[test]
    fn s5914_flags_typescript_test_files() {
        let source = "\
import { expect } from 'vitest';
expect(1 + 2).toBe(3);
";
        let keys = analyze(
            std::path::PathBuf::from("app.test.ts"),
            source,
            crate::JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        )
        .issues
        .into_iter()
        .map(|issue| (issue.rule_key, issue.range.start.line))
        .collect::<Vec<_>>();
        assert_eq!(count_key(&keys, "typescript:S5914"), 1);
    }

    #[test]
    fn s5914_ignores_meaningful_and_failing_assertions() {
        let source = "\
import { expect } from 'vitest';
import assert from 'node:assert';

expect(isReady()).toBeTruthy();
expect(findUser('missing')).not.toBeDefined();
expect(getUser()).toEqual({ id: 1 });
expect(false).toBeTruthy();
expect(0).toBe(1);
assert.ok(loadConfiguration());
assert.deepStrictEqual(readConfiguration(), { mode: 'test' });
";
        let keys = test_file_keys(source);
        assert_eq!(count_key(&keys, "javascript:S5914"), 0);
    }

    #[test]
    fn s5914_ignores_non_test_files() {
        let source = "\
import { expect } from 'vitest';
expect(true).toBeTruthy();
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S5914"), 0);
    }
}
