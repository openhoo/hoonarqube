use ruff_python_ast::{Decorator, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{dotted_name_is, for_each_stmt, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S9116";
const MESSAGE: &str = "Pass fixture options as keyword arguments.";

/// python:S9116 — positional options to `@pytest.fixture` (such as
/// `@pytest.fixture("module")`) were removed in pytest 6.0 and fail at
/// collection; options belong in keywords (`scope="module"`). The first
/// positional argument — including a `*args` unpacking — anchors the
/// finding; `**kwargs` keywords, keyword-only calls, the bare decorator, and
/// non-fixture decorators stay silent.
pub(crate) fn check_s9116_pytest_fixture_keyword_args(
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
            let Expr::Call(call) = &decorator.expression else {
                continue;
            };
            if !dotted_name_is(&call.func, "pytest.fixture") {
                continue;
            }
            if let Some(argument) = call.arguments.args.first() {
                issues.push(issue_at(RULE_KEY, MESSAGE, argument.range(), index, source));
            }
        }
    });
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan_test_file};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan_test_file(source), "python:S9116")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s9116_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: the positional `"module"` argument
        // anchors the finding (line 3, columns 16-24).
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.fixture(\"module\")\n",
            "def scoped():\n",
            "    return []\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(3, 16));
        assert_eq!(ranges[0].end, pos(3, 24));
    }

    #[test]
    fn s9116_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.fixture(scope=\"module\")\n",
                "def scoped():\n",
                "    return []\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s9116_flags_only_the_first_positional_argument() {
        // The reference reports once per decorator, on the first positional
        // argument; `*args` unpacking counts as positional.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.fixture(\"module\", \"extra\")\n",
            "def scoped():\n",
            "    return []\n",
            "\n",
            "@pytest.fixture(*options)\n",
            "def unpacked():\n",
            "    return []\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(3, 16));
        assert_eq!(ranges[0].end, pos(3, 24));
        assert_eq!(ranges[1].start, pos(7, 16));
        assert_eq!(ranges[1].end, pos(7, 24));
    }

    #[test]
    fn s9116_spares_keywords_bare_and_foreign_decorators() {
        // Keyword-only calls, `**kwargs`, the bare `@pytest.fixture`, and
        // positional arguments on other decorators stay silent.
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.fixture(scope=\"module\", autouse=True)\n",
                "def a():\n",
                "    return []\n",
                "\n",
                "@pytest.fixture(**options)\n",
                "def b():\n",
                "    return []\n",
                "\n",
                "@pytest.fixture\n",
                "def c():\n",
                "    return []\n",
                "\n",
                "@other.fixture(\"module\")\n",
                "def d():\n",
                "    return []\n",
            ))
            .is_empty()
        );
    }
}
