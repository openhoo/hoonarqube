use ruff_python_ast::{Decorator, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{dotted_name_is, dotted_name_parent_in, for_each_stmt, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S9074";
const MARK_ON_FIXTURE_MESSAGE: &str = "Remove this mark; it has no effect on fixtures.";
const EMPTY_USEFIXTURES_MESSAGE: &str =
    "Provide fixture names or remove this empty usefixtures decorator.";

/// python:S9074 — pytest marks only affect tests, classes, and modules, so a
/// `@pytest.mark.*` decorator on a `@pytest.fixture` function is silently
/// ignored, and `@pytest.mark.usefixtures()` with no fixture names is a
/// no-op on any function or class. Any `pytest.mark.<name>` decorator (bare
/// or called) on a fixture anchors "Remove this mark…" on the whole
/// decorator; an empty `usefixtures` call on a non-fixture function or class
/// anchors "Provide fixture names…" on the decorator. Marks on plain test
/// functions and `usefixtures` with names stay silent.
pub(crate) fn check_s9074_pytest_useless_marks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let (decorators, on_fixture): (&[Decorator], bool) = match stmt {
            Stmt::FunctionDef(function) => (
                &function.decorator_list,
                has_fixture_decorator(&function.decorator_list),
            ),
            Stmt::ClassDef(class) => (&class.decorator_list, false),
            _ => return,
        };
        for decorator in decorators {
            check_decorator(decorator, on_fixture, index, source, &mut issues);
        }
    });
    issues
}

fn check_decorator(
    decorator: &Decorator,
    on_fixture: bool,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let function_expression = match &decorator.expression {
        Expr::Call(call) => call.func.as_ref(),
        expression => expression,
    };
    if !is_pytest_mark(function_expression) {
        return;
    }
    if on_fixture {
        issues.push(issue_at(
            RULE_KEY,
            MARK_ON_FIXTURE_MESSAGE,
            decorator.range(),
            index,
            source,
        ));
    } else if is_empty_usefixtures(decorator, function_expression) {
        issues.push(issue_at(
            RULE_KEY,
            EMPTY_USEFIXTURES_MESSAGE,
            decorator.range(),
            index,
            source,
        ));
    }
}

/// `pytest.mark.<name>` — the qualifier decides, so every mark accessed on
/// `pytest.mark` counts (the reference also lists the known marks
/// `skip`/`xfail`/`parametrize`, which this shape already covers).
fn is_pytest_mark(expr: &Expr) -> bool {
    dotted_name_parent_in(expr, &["pytest.mark"])
}

/// `@pytest.mark.usefixtures()` — a call with an empty argument list.
fn is_empty_usefixtures(decorator: &Decorator, function_expression: &Expr) -> bool {
    if !dotted_name_is(function_expression, "pytest.mark.usefixtures") {
        return false;
    }
    match &decorator.expression {
        Expr::Call(call) => call.arguments.args.is_empty() && call.arguments.keywords.is_empty(),
        _ => false,
    }
}

/// Whether any decorator is `@pytest.fixture`, bare or called.
fn has_fixture_decorator(decorators: &[Decorator]) -> bool {
    decorators.iter().any(|decorator| {
        let expression = match &decorator.expression {
            Expr::Call(call) => call.func.as_ref(),
            expression => expression,
        };
        dotted_name_is(expression, "pytest.fixture")
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan_test_file};

    fn found(source: &str) -> Vec<(String, hoonarqube_ir::Range)> {
        findings(&scan_test_file(source), "python:S9074")
            .into_iter()
            .map(|issue| (issue.message.clone(), issue.range.clone()))
            .collect()
    }

    #[test]
    fn s9074_flags_marks_on_fixtures_and_empty_usefixtures() {
        // Sonar's Noncompliant examples: every `@pytest.mark.*` on a fixture
        // is flagged on the whole decorator (including the `@`), and an
        // empty `usefixtures()` on a test is flagged.
        let found = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.mark.asyncio\n",
            "@pytest.fixture\n",
            "async def db():\n",
            "    return await connect()\n",
            "\n",
            "@pytest.mark.usefixtures(\"db\")\n",
            "@pytest.fixture\n",
            "def client(db):\n",
            "    return Client(db)\n",
            "\n",
            "@pytest.mark.slow\n",
            "@pytest.fixture\n",
            "def cache():\n",
            "    return {}\n",
            "\n",
            "@pytest.mark.usefixtures()\n",
            "def test_ping():\n",
            "    assert ping() == \"pong\"\n",
        ));
        assert_eq!(found.len(), 4);
        assert_eq!(
            found[0].0,
            "Remove this mark; it has no effect on fixtures."
        );
        assert_eq!(found[0].1.start, pos(3, 0));
        assert_eq!(found[0].1.end, pos(3, 20));
        assert_eq!(found[1].1.start, pos(8, 0));
        assert_eq!(found[2].1.start, pos(13, 0));
        assert_eq!(
            found[3].0,
            "Provide fixture names or remove this empty usefixtures decorator."
        );
        assert_eq!(found[3].1.start, pos(18, 0));
        assert_eq!(found[3].1.end, pos(18, 26));
    }

    #[test]
    fn s9074_accepts_the_sonar_compliant_examples() {
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.fixture\n",
                "async def db():\n",
                "    return await connect()\n",
                "\n",
                "@pytest.fixture\n",
                "def client(db):\n",
                "    return Client(db)\n",
                "\n",
                "@pytest.fixture\n",
                "def cache():\n",
                "    return {}\n",
                "\n",
                "def test_ping():\n",
                "    assert ping() == \"pong\"\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s9074_flags_empty_usefixtures_on_classes_and_called_marks_on_fixtures() {
        // Empty `usefixtures()` on a class is flagged; a called mark like
        // `@pytest.mark.skip(reason="x")` on a fixture is still useless.
        let found = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.mark.usefixtures()\n",
            "class TestSuite:\n",
            "    def test_a(self):\n",
            "        pass\n",
            "\n",
            "@pytest.mark.skip(reason=\"not ready\")\n",
            "@pytest.fixture\n",
            "def skipped_fixture():\n",
            "    return 1\n",
        ));
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].0,
            "Provide fixture names or remove this empty usefixtures decorator."
        );
        assert_eq!(
            found[1].0,
            "Remove this mark; it has no effect on fixtures."
        );
        assert_eq!(found[1].1.start, pos(8, 0));
    }

    #[test]
    fn s9074_spares_real_marks_and_named_usefixtures() {
        // Marks on test functions, `usefixtures` with names, the bare
        // `usefixtures` attribute (not a call), and non-pytest decorators
        // stay silent.
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.mark.slow\n",
                "def test_slow():\n",
                "    pass\n",
                "\n",
                "@pytest.mark.usefixtures(\"db\")\n",
                "def test_uses_db():\n",
                "    pass\n",
                "\n",
                "@pytest.mark.usefixtures\n",
                "def test_bare():\n",
                "    pass\n",
                "\n",
                "@other.mark.skip\n",
                "@pytest.fixture\n",
                "def foreign():\n",
                "    return 1\n",
            ))
            .is_empty()
        );
    }
}
