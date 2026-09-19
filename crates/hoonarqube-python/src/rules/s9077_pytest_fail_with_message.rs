use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{
    dotted_name_is, for_each_stmt, for_each_stmt_expr, issue_at, string_value_text,
};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S9077";
const ASSERT_MESSAGE: &str = "Replace this assertion with pytest.fail(...) and provide a message.";
const FAIL_MESSAGE: &str = "Add a message explaining why this test fails.";

/// python:S9077 — an intentional abort should say why: `assert False` and
/// `assert 0` look like accidental logic bugs, and `pytest.fail()` without a
/// message leaves nothing to triage. Assert statements flag only when the
/// file imports pytest (any `import pytest…`/`from pytest…` form, matching
/// the reference's import visitor) and the condition is the `False` name or
/// an integral zero literal (`0`, `0.0`; `0j` is not an integer and stays
/// silent) — with or without an assert message. `pytest.fail(...)` flags
/// when its first positional/`reason=`/`msg=` argument is missing or an
/// empty/whitespace string. The assert statement and the fail call anchor
/// their findings.
pub(crate) fn check_s9077_pytest_fail_with_message(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let pytest_imported = imports_pytest(parsed.syntax().body.as_slice());
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Assert(assert_stmt) = stmt
            && pytest_imported
            && is_false_or_zero_literal(&assert_stmt.test)
        {
            issues.push(issue_at(
                RULE_KEY,
                ASSERT_MESSAGE,
                assert_stmt.range(),
                index,
                source,
            ));
        }
    });
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Call(call) = expr {
            check_fail_call(call, index, source, &mut issues);
        }
    });
    issues
}

/// `pytest.fail(...)` calls anywhere a call expression appears — the
/// reference subscribes to call expressions, not just expression statements.
fn check_fail_call(
    call: &ruff_python_ast::ExprCall,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !dotted_name_is(&call.func, "pytest.fail") {
        return;
    }
    if has_no_message(call) {
        issues.push(issue_at(
            RULE_KEY,
            FAIL_MESSAGE,
            call.range(),
            index,
            source,
        ));
    }
}

/// `messageArgument` + `hasNoMessage`: the first positional argument wins,
/// then `reason=`, then `msg=`; missing or an empty/whitespace-only string
/// literal counts as no message.
fn has_no_message(call: &ruff_python_ast::ExprCall) -> bool {
    let message = call
        .arguments
        .args
        .first()
        .filter(|arg| !arg.is_starred_expr())
        .or_else(|| keyword_value(call, "reason"))
        .or_else(|| keyword_value(call, "msg"));
    match message {
        None => true,
        Some(Expr::StringLiteral(literal)) => string_value_text(&literal.value).trim().is_empty(),
        Some(_) => false,
    }
}

fn keyword_value<'a>(call: &'a ruff_python_ast::ExprCall, name: &str) -> Option<&'a Expr> {
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some(name))
        .map(|keyword| &keyword.value)
}

/// The `False` name or an integral zero literal (`0`, `0.0`; complex `0j`
/// throws in the reference and stays silent).
fn is_false_or_zero_literal(expr: &Expr) -> bool {
    match expr {
        Expr::BooleanLiteral(boolean) => !boolean.value,
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64() == Some(0),
            ruff_python_ast::Number::Float(value) => *value == 0.0,
            ruff_python_ast::Number::Complex { .. } => false,
        },
        _ => false,
    }
}

/// The reference's `PytestImportVisitor`: any `import pytest…` or
/// `from pytest…` statement (first dotted segment `pytest`, any alias or
/// relative level) marks the file as pytest-importing.
fn imports_pytest(stmts: &[Stmt]) -> bool {
    let mut found = false;
    for_each_stmt(stmts, &mut |stmt| {
        if found {
            return;
        }
        match stmt {
            Stmt::Import(import)
                if import
                    .names
                    .iter()
                    .any(|alias| is_pytest_module(alias.name.as_str())) =>
            {
                found = true;
            }
            Stmt::ImportFrom(import)
                if import
                    .module
                    .as_ref()
                    .is_some_and(|module| is_pytest_module(module.as_str())) =>
            {
                found = true;
            }
            _ => {}
        }
    });
    found
}

/// Whether the dotted module name's first segment is `pytest`.
fn is_pytest_module(dotted: &str) -> bool {
    dotted.split('.').next() == Some("pytest")
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan_test_file};

    fn found(source: &str) -> Vec<(String, hoonarqube_ir::Range)> {
        findings(&scan_test_file(source), "python:S9077")
            .into_iter()
            .map(|issue| (issue.message.clone(), issue.range.clone()))
            .collect()
    }

    #[test]
    fn s9077_flags_the_sonar_noncompliant_examples() {
        // `assert False` anchors the assert statement (line 4, columns 4-16);
        // `pytest.fail()` anchors the call (line 7, columns 4-17).
        let found = found(concat!(
            "import pytest\n",
            "\n",
            "def test_not_ready():\n",
            "    assert False\n",
            "\n",
            "def test_blocked():\n",
            "    pytest.fail()\n",
        ));
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].0,
            "Replace this assertion with pytest.fail(...) and provide a message."
        );
        assert_eq!(found[0].1.start, pos(4, 4));
        assert_eq!(found[0].1.end, pos(4, 16));
        assert_eq!(found[1].0, "Add a message explaining why this test fails.");
        assert_eq!(found[1].1.start, pos(7, 4));
        assert_eq!(found[1].1.end, pos(7, 17));
    }

    #[test]
    fn s9077_accepts_the_sonar_compliant_examples() {
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "def test_not_ready():\n",
                "    pytest.fail(\"feature not implemented yet\")\n",
                "\n",
                "def test_blocked():\n",
                "    pytest.fail(\"blocked on issue 42\")\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s9077_flags_zero_and_empty_or_blank_messages() {
        // `assert 0` and `assert 0.0` count (integral zeros); `fail("")`,
        // `fail("   ")`, `fail(reason="")`, and `fail(msg=" ")` have no
        // usable message.
        let found = found(concat!(
            "import pytest\n",
            "\n",
            "def test_a():\n",
            "    assert 0\n",
            "def test_b():\n",
            "    assert 0.0\n",
            "def test_c():\n",
            "    pytest.fail(\"\")\n",
            "def test_d():\n",
            "    pytest.fail(\"   \")\n",
            "def test_e():\n",
            "    pytest.fail(reason=\"\")\n",
            "def test_f():\n",
            "    pytest.fail(msg=\" \")\n",
        ));
        assert_eq!(found.len(), 6);
    }

    #[test]
    fn s9077_spares_real_assertions_messages_and_missing_import() {
        // Truthy/other asserts, `fail` with a positional or keyword message,
        // `fail(pytest.param(...))`, and `assert False` in a file that never
        // imports pytest stay silent.
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "def test_a():\n",
                "    assert compute() == 3\n",
                "    assert 1\n",
                "    assert 0j\n",
                "def test_b():\n",
                "    pytest.fail(\"why\")\n",
                "    pytest.fail(reason=\"why\")\n",
                "    pytest.fail(msg=\"why\")\n",
                "    pytest.fail(pytest.param(1))\n",
            ))
            .is_empty()
        );
        assert!(found("def test_a():\n    assert False\n").is_empty());
    }
}
