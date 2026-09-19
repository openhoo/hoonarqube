use std::collections::HashSet;
use std::path::Path;

use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtClassDef, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::support::{
    class_is_testcase_subclass, dotted_name, flow_location, is_pytest_file_name, issue_at,
};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S5976";
const MESSAGE: &str = "Group these similar tests into a single parameterized test.";
const SECONDARY_MESSAGE: &str = "Similar test.";
const MIN_GROUP_SIZE: usize = 3;
const MAX_PARAMETER_COUNT: usize = 3;

/// python:S5976 — three or more sibling test functions whose bodies differ
/// only in literal values should be one parameterized test. The reference
/// compares the body trees node-by-node, tolerating up to three distinct
/// literal differences (numeric, string, `None`, boolean); hoonarqube
/// performs the equivalent comparison over each body's token stream, where
/// trivia is dropped and differing tokens must both be parameterizable
/// literals of the same literal class. Candidates are undecorated `test*`
/// functions that are pytest-style (pytest file name, module level or `Test*`
/// class) or `unittest.TestCase` methods; `pass`-only and
/// `raise NotImplementedError` placeholders are excluded. Names must share
/// the same stem after stripping trailing digits, and parameters must be
/// textually identical. The first test of a group anchors the finding; the
/// remaining members are secondary locations.
pub(crate) fn check_s5976_similar_tests_parameterized(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    let pytest_file = is_pytest_file_name(path);
    let mut issues = Vec::new();
    // Each suite with the class whose body it is (`None` = module body). The
    // reference scans module and class bodies only, so function bodies are
    // never queued and nested tests inside functions are not candidates.
    let mut pending: Vec<(&[Stmt], Option<&StmtClassDef>)> =
        vec![(parsed.syntax().body.as_slice(), None)];
    while let Some((stmts, parent_class)) = pending.pop() {
        check_suite(
            stmts,
            parent_class,
            pytest_file,
            parsed,
            index,
            source,
            &mut issues,
        );
        for stmt in stmts {
            if let Stmt::ClassDef(class) = stmt {
                pending.push((class.body.as_slice(), Some(class)));
            }
        }
    }
    issues
}

/// One candidate test function plus whether its nearest enclosing class is a
/// `unittest.TestCase` subclass (the reference's `sameTestKind` input).
struct Candidate<'a> {
    function: &'a StmtFunctionDef,
    in_testcase: bool,
}

/// Groups the candidate tests of one suite and emits one finding per group of
/// at least three similar tests. Grouping is anchor-based: the first
/// unreported candidate collects every later similar sibling, and group
/// members cannot anchor their own group.
fn check_suite(
    stmts: &[Stmt],
    parent_class: Option<&StmtClassDef>,
    pytest_file: bool,
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let in_testcase = parent_class.is_some_and(class_is_testcase_subclass);
    let pytest_style =
        pytest_file && parent_class.is_none_or(|class| class.name.as_str().starts_with("Test"));
    let candidates: Vec<Candidate> = stmts
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::FunctionDef(function) if is_candidate(function, in_testcase || pytest_style) => {
                Some(Candidate {
                    function,
                    in_testcase,
                })
            }
            _ => None,
        })
        .collect();
    let mut reported: HashSet<usize> = HashSet::new();
    for (i, anchor) in candidates.iter().enumerate() {
        if reported.contains(&i) {
            continue;
        }
        let mut group: Vec<usize> = vec![i];
        for (j, candidate) in candidates.iter().enumerate().skip(i + 1) {
            if are_similar_tests(anchor, candidate, parsed, source) {
                group.push(j);
            }
        }
        if group.len() >= MIN_GROUP_SIZE {
            let mut issue = issue_at(
                RULE_KEY,
                MESSAGE,
                anchor.function.name.range(),
                index,
                source,
            );
            issue = issue.with_flow(
                group
                    .iter()
                    .skip(1)
                    .map(|member| {
                        flow_location(
                            SECONDARY_MESSAGE,
                            candidates[*member].function.name.range(),
                            index,
                            source,
                        )
                    })
                    .collect(),
            );
            issues.push(issue);
            reported.extend(group);
        }
    }
}

/// Whether `function` is a candidate: `test*` name, no decorators, not a
/// placeholder, and eligible under either test kind (the caller computes
/// `unittest.TestCase` membership and pytest-style eligibility for the
/// suite).
fn is_candidate(function: &StmtFunctionDef, eligible: bool) -> bool {
    eligible
        && function.name.as_str().starts_with("test")
        && function.decorator_list.is_empty()
        && !is_placeholder_test(function)
}

/// `isPlaceholderTest`: a single `pass` statement or a single
/// `raise NotImplementedError` (bare or called, without a `from` cause).
fn is_placeholder_test(function: &StmtFunctionDef) -> bool {
    let [stmt] = function.body.as_slice() else {
        return false;
    };
    match stmt {
        Stmt::Pass(_) => true,
        Stmt::Raise(raise) => {
            raise.cause.is_none() && raise.exc.as_deref().is_some_and(is_not_implemented_error)
        }
        _ => false,
    }
}

/// Whether `expr` is `NotImplementedError` or `NotImplementedError(...)`.
fn is_not_implemented_error(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => dotted_name(&call.func).as_deref() == Some("NotImplementedError"),
        _ => dotted_name(expr).as_deref() == Some("NotImplementedError"),
    }
}

/// `areSimilarTests`: same digit-stripped name stem, same test kind,
/// textually identical parameters, and bodies equal up to at most three
/// distinct parameterizable-literal differences.
fn are_similar_tests(
    left: &Candidate,
    right: &Candidate,
    parsed: &Parsed<ModModule>,
    source: &str,
) -> bool {
    if normalize_name(left.function) != normalize_name(right.function) {
        return false;
    }
    if left.in_testcase != right.in_testcase {
        return false;
    }
    if !equivalent_tokens(
        &tokens_in(parsed, left.function.parameters.range(), source),
        &tokens_in(parsed, right.function.parameters.range(), source),
    ) {
        return false;
    }
    similar_bodies(parsed, left.function, right.function, source)
}

/// The function name without its trailing ASCII digits (`test_level12` and
/// `test_level3` share the stem `test_level`).
fn normalize_name(function: &StmtFunctionDef) -> &str {
    function
        .name
        .as_str()
        .trim_end_matches(|c: char| c.is_ascii_digit())
}

/// Non-trivia tokens fully inside `range` as (kind, text) pairs. Comments and
/// non-logical newlines are dropped, matching the reference's tree comparison
/// which sees neither.
fn tokens_in<'a>(
    parsed: &'a Parsed<ModModule>,
    range: TextRange,
    source: &'a str,
) -> Vec<(TokenKind, &'a str)> {
    parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia() && range.contains_range(token.range()))
        .map(|token| (token.kind(), &source[token.range()]))
        .collect()
}

/// Strict token equality for parameter lists (`CheckUtils.areEquivalent`):
/// every token kind and text must match.
fn equivalent_tokens(left: &[(TokenKind, &str)], right: &[(TokenKind, &str)]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(l, r)| l == r)
}

/// `DifferenceCounter.areSimilar` over the two bodies' token streams: equal
/// length, and every differing position must pair two parameterizable
/// literals of the same class, with at most three distinct differences.
fn similar_bodies(
    parsed: &Parsed<ModModule>,
    left: &StmtFunctionDef,
    right: &StmtFunctionDef,
    source: &str,
) -> bool {
    let left_tokens = tokens_in(parsed, body_range(left), source);
    let right_tokens = tokens_in(parsed, body_range(right), source);
    if left_tokens.len() != right_tokens.len() {
        return false;
    }
    let mut differences: HashSet<(LiteralClass, &str, &str)> = HashSet::new();
    for (&(left_kind, left_text), &(right_kind, right_text)) in
        left_tokens.iter().zip(right_tokens.iter())
    {
        if left_kind == right_kind && left_text == right_text {
            continue;
        }
        // The reference treats INDENT/DEDENT leaves as always equal.
        if matches!(left_kind, TokenKind::Indent | TokenKind::Dedent) {
            continue;
        }
        let (Some(class), Some(right_class)) =
            (literal_class(left_kind), literal_class(right_kind))
        else {
            return false;
        };
        if class != right_class {
            return false;
        }
        differences.insert((class, left_text, right_text));
        if differences.len() > MAX_PARAMETER_COUNT {
            return false;
        }
    }
    true
}

/// The token range covering the function body statements.
fn body_range(function: &StmtFunctionDef) -> TextRange {
    let start = function
        .body
        .first()
        .map_or(function.range(), Ranged::range);
    let end = function.body.last().map_or(function.range(), Ranged::range);
    TextRange::new(start.start(), end.end())
}

/// The literal classes the reference accepts as parameterizable differences:
/// numeric literals, string literals (including bytes and f-string literal
/// text), `None`, and boolean literals. Everything else — names, operators,
/// keywords — must match exactly.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum LiteralClass {
    Numeric,
    String,
    FStringText,
    NoneLiteral,
    Boolean,
}

fn literal_class(kind: TokenKind) -> Option<LiteralClass> {
    match kind {
        TokenKind::Int | TokenKind::Float | TokenKind::Complex => Some(LiteralClass::Numeric),
        TokenKind::String => Some(LiteralClass::String),
        TokenKind::FStringMiddle | TokenKind::TStringMiddle => Some(LiteralClass::FStringText),
        TokenKind::None => Some(LiteralClass::NoneLiteral),
        TokenKind::True | TokenKind::False => Some(LiteralClass::Boolean),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{findings, pos, scan, scan_at, scan_test_file};

    const KEY: &str = "python:S5976";

    #[test]
    fn s5976_flags_three_similar_tests() {
        let report = scan_test_file(
            "def setup_tax():\n\
             \x20   pass\n\
             \n\
             def get_tax(value):\n\
             \x20   return value\n\
             \n\
             def test_not_null1():\n\
             \x20   setup_tax()\n\
             \x20   assert get_tax(1) is not None\n\
             \n\
             def test_not_null2():\n\
             \x20   setup_tax()\n\
             \x20   assert get_tax(2) is not None\n\
             \n\
             def test_not_null3():\n\
             \x20   setup_tax()\n\
             \x20   assert get_tax(3) is not None\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start, pos(7, 4));
        assert_eq!(hits[0].range.end, pos(7, 18));
        assert_eq!(hits[0].flows.len(), 1);
        assert_eq!(hits[0].flows[0].locations.len(), 2);
    }

    #[test]
    fn s5976_flags_class_and_unittest_members() {
        let report = scan_test_file(
            "import unittest\n\
             \n\
             class TestApp:\n\
             \x20   def test_level1(self):\n\
             \x20       set_level(1)\n\
             \x20       assert player_health() == 100\n\
             \x20   def test_level2(self):\n\
             \x20       set_level(2)\n\
             \x20       assert player_health() == 200\n\
             \x20   def test_level3(self):\n\
             \x20       set_level(3)\n\
             \x20       assert player_health() == 300\n\
             \n\
             class TestUnittestApp(unittest.TestCase):\n\
             \x20   def test_user1(self):\n\
             \x20       self.assertIsNotNone(get_tax(1))\n\
             \x20   def test_user2(self):\n\
             \x20       self.assertIsNotNone(get_tax(2))\n\
             \x20   def test_user3(self):\n\
             \x20       self.assertIsNotNone(get_tax(3))\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].range.start, pos(4, 8));
        assert_eq!(hits[1].range.start, pos(15, 8));
    }

    #[test]
    fn s5976_flags_unittest_classes_in_non_test_files() {
        let report = scan(
            "import unittest\n\
             \n\
             class TestApp(unittest.TestCase):\n\
             \x20   def test_not_null1(self):\n\
             \x20       setup_tax()\n\
             \x20       self.assertIsNotNone(get_tax(1))\n\
             \x20   def test_not_null2(self):\n\
             \x20       setup_tax()\n\
             \x20       self.assertIsNotNone(get_tax(2))\n\
             \x20   def test_not_null3(self):\n\
             \x20       setup_tax()\n\
             \x20       self.assertIsNotNone(get_tax(3))\n",
        );
        assert_eq!(findings(&report, KEY).len(), 1);
    }

    #[test]
    fn s5976_ignores_module_level_tests_in_non_test_files() {
        let report = scan(
            "def test_a1():\n    assert get_tax(1)\n\
             def test_a2():\n    assert get_tax(2)\n\
             def test_a3():\n    assert get_tax(3)\n",
        );
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s5976_ignores_pairs_decorated_and_placeholder_tests() {
        let report = scan_test_file(
            "import pytest\n\
             \n\
             def test_only_two_cases_1():\n\
             \x20   assert get_tax(1) is not None\n\
             \n\
             def test_only_two_cases_2():\n\
             \x20   assert get_tax(2) is not None\n\
             \n\
             @pytest.mark.slow\n\
             def test_decorated_1():\n\
             \x20   assert get_tax(1) is not None\n\
             \n\
             @pytest.mark.slow\n\
             def test_decorated_2():\n\
             \x20   assert get_tax(2) is not None\n\
             \n\
             @pytest.mark.slow\n\
             def test_decorated_3():\n\
             \x20   assert get_tax(3) is not None\n\
             \n\
             def test_placeholder1():\n\
             \x20   pass\n\
             \n\
             def test_placeholder2():\n\
             \x20   pass\n\
             \n\
             def test_placeholder3():\n\
             \x20   pass\n\
             \n\
             def test_not_implemented1():\n\
             \x20   raise NotImplementedError\n\
             \n\
             def test_not_implemented2():\n\
             \x20   raise NotImplementedError()\n\
             \n\
             def test_not_implemented3():\n\
             \x20   raise NotImplementedError(\"todo\")\n",
        );
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s5976_ignores_structural_and_parameter_differences() {
        let report = scan_test_file(
            "def test_parameter_mismatch_1(user_id):\n\
             \x20   assert get_tax(user_id) is not None\n\
             \n\
             def test_parameter_mismatch_2(account_id):\n\
             \x20   assert get_tax(account_id) is not None\n\
             \n\
             def test_parameter_mismatch_3(customer_id):\n\
             \x20   assert get_tax(customer_id) is not None\n\
             \n\
             def test_non_literal_leaf_difference_1():\n\
             \x20   tax = 1\n\
             \x20   assert get_tax(tax) is not None\n\
             \n\
             def test_non_literal_leaf_difference_2():\n\
             \x20   value = 1\n\
             \x20   assert get_tax(value) is not None\n\
             \n\
             def test_non_literal_leaf_difference_3():\n\
             \x20   amount = 1\n\
             \x20   assert get_tax(amount) is not None\n\
             \n\
             def test_more_than_three_literal_differences_1():\n\
             \x20   assert get_tax(1) == (\"alpha\", True, None, 1)\n\
             \n\
             def test_more_than_three_literal_differences_2():\n\
             \x20   assert get_tax(2) == (\"beta\", False, 1, 2)\n\
             \n\
             def test_more_than_three_literal_differences_3():\n\
             \x20   assert get_tax(3) == (\"gamma\", True, 2, 3)\n",
        );
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s5976_repeated_literal_counts_once() {
        let report = scan_test_file(
            "def test_repeated_parameter_difference_1():\n\
             \x20   assert (1, 1, 1, 1) == (1, 1, 1, 1)\n\
             \n\
             def test_repeated_parameter_difference_2():\n\
             \x20   assert (2, 2, 2, 2) == (2, 2, 2, 2)\n\
             \n\
             def test_repeated_parameter_difference_3():\n\
             \x20   assert (3, 3, 3, 3) == (3, 3, 3, 3)\n",
        );
        assert_eq!(findings(&report, KEY).len(), 1);
    }

    #[test]
    fn s5976_flags_nested_test_classes_and_ignores_helpers() {
        let report = scan_test_file(
            "class HelperContainer:\n\
             \x20   def test_helper1(self):\n\
             \x20       assert get_tax(1) is not None\n\
             \x20   def test_helper2(self):\n\
             \x20       assert get_tax(2) is not None\n\
             \x20   def test_helper3(self):\n\
             \x20       assert get_tax(3) is not None\n\
             \n\
             class TestNestedContainer:\n\
             \x20   class TestInner:\n\
             \x20       def test_nested_tax1(self):\n\
             \x20           assert get_tax(1) is not None\n\
             \x20       def test_nested_tax2(self):\n\
             \x20           assert get_tax(2) is not None\n\
             \x20       def test_nested_tax3(self):\n\
             \x20           assert get_tax(3) is not None\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start, pos(11, 12));
    }

    #[test]
    fn s5976_ignores_different_name_stems_and_arity() {
        let report = scan_test_file(
            "def test_call_with_different_arity_1():\n\
             \x20   assert get_tax(1) == 1\n\
             \n\
             def test_call_with_different_arity_2():\n\
             \x20   assert get_tax(1, 2) == 1\n\
             \n\
             def test_call_with_different_arity_3():\n\
             \x20   assert get_tax(1, 2, 3) == 1\n\
             \n\
             def test_alpha_1():\n\
             \x20   assert get_tax(1)\n\
             \n\
             def test_beta_2():\n\
             \x20   assert get_tax(2)\n\
             \n\
             def test_gamma_3():\n\
             \x20   assert get_tax(3)\n",
        );
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s5976_string_and_boolean_differences() {
        let report = scan_test_file(
            "def test_string_difference_1():\n\
             \x20   assert get_tax(\"alpha\") is not None\n\
             \n\
             def test_string_difference_2():\n\
             \x20   assert get_tax(\"beta\") is not None\n\
             \n\
             def test_string_difference_3():\n\
             \x20   assert get_tax(\"gamma\") is not None\n\
             \n\
             import unittest\n\
             class LegacySuite(unittest.TestCase):\n\
             \x20   def test_legacy_user1(self):\n\
             \x20       self.assertEqual(get_tax(True), True)\n\
             \x20   def test_legacy_user2(self):\n\
             \x20       self.assertEqual(get_tax(False), False)\n\
             \x20   def test_legacy_user3(self):\n\
             \x20       self.assertEqual(get_tax(True), True)\n",
        );
        assert_eq!(findings(&report, KEY).len(), 2);
    }

    #[test]
    fn s5976_ignores_conftest() {
        let report = scan_at(
            PathBuf::from("conftest.py"),
            "def test_a1():\n    assert f(1)\n\
             def test_a2():\n    assert f(2)\n\
             def test_a3():\n    assert f(3)\n",
        );
        // conftest.py is not a pytest file name and not a TestCase class, so
        // module-level tests there are not candidates.
        assert!(findings(&report, KEY).is_empty());
    }
}
