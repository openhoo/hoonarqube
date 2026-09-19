use ruff_python_ast::{Decorator, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{dotted_name_is, for_each_stmt, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S9076";
const MESSAGE: &str = "Replace deprecated pytest.yield_fixture with pytest.fixture.";

/// python:S9076 — `@pytest.yield_fixture` is a deprecated pre-3.0 alias of
/// `@pytest.fixture`, which supports yield for setup and teardown. The
/// decorator expression anchors the finding: the bare attribute
/// `@pytest.yield_fixture` and the called form `@pytest.yield_fixture(...)`
/// both report on the whole expression (the call included). Other fixture
/// decorators and `yield_fixture` spellings outside `pytest` stay silent.
pub(crate) fn check_s9076_pytest_yield_fixture_deprecated(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let decorators: &[Decorator] = match stmt {
            Stmt::FunctionDef(function) => &function.decorator_list,
            Stmt::ClassDef(class) => &class.decorator_list,
            _ => return,
        };
        for decorator in decorators {
            let expression = &decorator.expression;
            let callee = match expression {
                Expr::Call(call) => call.func.as_ref(),
                expression => expression,
            };
            if dotted_name_is(callee, "pytest.yield_fixture") {
                issues.push(issue_at(
                    RULE_KEY,
                    MESSAGE,
                    expression.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan_test_file};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan_test_file(source), "python:S9076")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s9076_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: the bare `@pytest.yield_fixture`
        // expression anchors the finding (line 3, columns 1-22 — the
        // expression without the `@`).
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.yield_fixture\n",
            "def old_style():\n",
            "    value = 1\n",
            "    yield value\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(3, 1));
        assert_eq!(ranges[0].end, pos(3, 21));
    }

    #[test]
    fn s9076_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.fixture\n",
                "def old_style():\n",
                "    value = 1\n",
                "    yield value\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s9076_flags_the_called_form_on_the_whole_call() {
        // `@pytest.yield_fixture(...)` reports on the call expression, not
        // just the callee.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.yield_fixture(scope=\"module\")\n",
            "def old_style():\n",
            "    yield 1\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(3, 1));
        assert_eq!(ranges[0].end, pos(3, 37));
    }

    #[test]
    fn s9076_spares_fixture_and_foreign_yield_fixture() {
        // `pytest.fixture` (bare and called), `pytest.mark.*`, and a
        // `yield_fixture` attribute on another module stay silent.
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.fixture\n",
                "def a():\n",
                "    yield 1\n",
                "\n",
                "@pytest.fixture(params=[1])\n",
                "def b(request):\n",
                "    yield request.param\n",
                "\n",
                "@other.yield_fixture\n",
                "def c():\n",
                "    yield 1\n",
            ))
            .is_empty()
        );
    }
}
