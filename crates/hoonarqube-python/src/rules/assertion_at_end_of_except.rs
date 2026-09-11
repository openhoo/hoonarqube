use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ExprCall;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextSize};

const ASSERT_METHODS: &[&str] = &[
    "assertEqual",
    "assertNotEqual",
    "assertTrue",
    "assertFalse",
    "assertIs",
    "assertIsNot",
    "assertIsNone",
    "assertIsNotNone",
    "assertIn",
    "assertNotIn",
    "assertIsInstance",
    "assertNotIsInstance",
    "assertAlmostEqual",
    "assertNotAlmostEqual",
    "assertGreater",
    "assertGreaterEqual",
    "assertLess",
    "assertLessEqual",
    "assertRegex",
    "assertNotRegex",
    "assertCountEqual",
    "assertMultiLineEqual",
    "assertSequenceEqual",
    "assertListEqual",
    "assertTupleEqual",
    "assertSetEqual",
    "assertDictEqual",
    "assertDictContainsSubset",
    "assertWarns",
    "assertWarnsRegex",
    "assertLogs",
    "assertNoLogs",
    "assertRaises",
    "assertRaisesRegex",
    "assertRaisesRegexp",
];
const RAISE_METHODS: &[&str] = &["assertRaises", "assertRaisesRegex", "assertRaisesRegexp"];

pub(crate) fn check_assertion_at_end_of_except(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::With(with_stmt) = stmt else {
            continue;
        };
        let Some(last) = with_stmt.body.last() else {
            continue;
        };
        if !is_assert_statement(last) {
            continue;
        }
        let Some(message) = (with_stmt.items.iter().any(|item| {
            let Expr::Call(call) = &item.context_expr else { return false };
            is_pytest_raise(call, file_ctx) || is_unittest_raise(call)
        }))
        .then(|| {
            if with_stmt.body.len() > 1 {
                "Don’t perform an assertion here; An exception is expected to be raised before its execution."
            } else {
                "Refactor this test; if this assertion’s argument raises an exception, the assertion will never get executed."
            }
        }) else {
            continue;
        };
        issues.push(issue_at(
            "python:S5915",
            message,
            last.range(),
            index,
            source,
        ));
    }
    issues
}

fn is_assert_statement(stmt: &Stmt) -> bool {
    if matches!(stmt, Stmt::Assert(_)) {
        return true;
    }
    let Stmt::Expr(value) = stmt else {
        return false;
    };
    let Expr::Call(call) = value.value.as_ref() else {
        return false;
    };
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return false;
    };
    matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
        && ASSERT_METHODS.contains(&attribute.attr.as_str())
}

fn is_pytest_raise(call: &ExprCall, file_ctx: &FileContext) -> bool {
    let Some(path) = dotted_name(&call.func) else {
        return false;
    };
    if resolve_imported_path(file_ctx, &path, call.range().start()).as_deref()
        != Some("pytest.raises")
    {
        return false;
    }
    let Some(expected) = call
        .arguments
        .find_keyword("expected_exception")
        .map(|keyword| &keyword.value)
        .or_else(|| call.arguments.args.first())
    else {
        return false;
    };
    !is_assertion_error(expected)
}

fn is_unittest_raise(call: &ExprCall) -> bool {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return false;
    };
    let Expr::Name(receiver) = attribute.value.as_ref() else {
        return false;
    };
    receiver.id.as_str() == "self"
        && RAISE_METHODS.contains(&attribute.attr.as_str())
        && call
            .arguments
            .find_keyword("exception")
            .map(|keyword| &keyword.value)
            .or_else(|| call.arguments.args.first())
            .is_some_and(|expected| !is_assertion_error(expected))
}

fn is_assertion_error(expr: &Expr) -> bool {
    matches!(
        dotted_name(expr).as_deref(),
        Some("AssertionError" | "builtins.AssertionError")
    )
}

fn dotted_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(name) => Some(name.id.to_string()),
        Expr::Attribute(attribute) => Some(format!(
            "{}.{}",
            dotted_name(&attribute.value)?,
            attribute.attr
        )),
        _ => None,
    }
}

fn resolve_imported_path(file_ctx: &FileContext, path: &str, at: TextSize) -> Option<String> {
    file_ctx
        .imports
        .iter()
        .filter_map(|entry| resolve_import_entry(file_ctx, path, at, entry))
        .fold(None, |best, candidate| {
            Some(choose_latest_candidate(best, candidate))
        })
        .map(|(_, resolved)| resolved)
}

fn choose_latest_candidate(
    best: Option<(TextSize, String)>,
    candidate: (TextSize, String),
) -> (TextSize, String) {
    match best {
        Some(previous) if candidate.0 <= previous.0 => previous,
        _ => candidate,
    }
}

fn resolve_import_entry(
    file_ctx: &FileContext,
    path: &str,
    at: TextSize,
    entry: &AnyImport<'_>,
) -> Option<(TextSize, String)> {
    match entry {
        AnyImport::Plain(import) => resolve_plain_import(file_ctx, path, at, import),
        AnyImport::From(import) => resolve_from_import(file_ctx, path, at, import),
    }
}

fn resolve_plain_import(
    file_ctx: &FileContext,
    path: &str,
    at: TextSize,
    import: &ruff_python_ast::StmtImport,
) -> Option<(TextSize, String)> {
    import
        .names
        .iter()
        .filter_map(|alias| {
            if alias.range.start() >= at {
                return None;
            }
            let full = alias.name.as_str();
            let bound = alias.asname.as_ref().map_or_else(
                || full.split('.').next().unwrap_or_default(),
                |name| name.as_str(),
            );
            let resolved = resolve_plain_path(path, full, bound)?;
            if import_binding_shadowed(file_ctx, bound, alias.range.end(), at) {
                return None;
            }
            Some((alias.range.start(), resolved))
        })
        .fold(None, |best, candidate| {
            Some(choose_latest_candidate(best, candidate))
        })
}

fn resolve_from_import(
    file_ctx: &FileContext,
    path: &str,
    at: TextSize,
    import: &ruff_python_ast::StmtImportFrom,
) -> Option<(TextSize, String)> {
    if import.level != 0 {
        return None;
    }
    let module = import.module.as_ref()?.as_str();
    import
        .names
        .iter()
        .filter_map(|alias| {
            if alias.range.start() >= at {
                return None;
            }
            let bound = alias
                .asname
                .as_ref()
                .map_or(alias.name.as_str(), |name| name.as_str());
            let resolved = resolve_from_path(path, module, alias.name.as_str(), bound)?;
            if import_binding_shadowed(file_ctx, bound, alias.range.end(), at) {
                return None;
            }
            Some((alias.range.start(), resolved))
        })
        .fold(None, |best, candidate| {
            Some(choose_latest_candidate(best, candidate))
        })
}

fn resolve_plain_path(path: &str, full: &str, bound: &str) -> Option<String> {
    if path == full || path.starts_with(&format!("{full}.")) {
        return Some(path.to_string());
    }
    if path == bound {
        return Some(full.to_string());
    }
    let suffix = path.strip_prefix(&format!("{bound}."))?;
    Some(format!("{full}.{suffix}"))
}

fn resolve_from_path(path: &str, module: &str, imported: &str, bound: &str) -> Option<String> {
    if path == bound {
        return Some(format!("{module}.{imported}"));
    }
    let suffix = path.strip_prefix(&format!("{bound}."))?;
    Some(format!("{module}.{imported}.{suffix}"))
}

fn import_binding_shadowed(
    file_ctx: &FileContext,
    bound: &str,
    import_end: TextSize,
    at: TextSize,
) -> bool {
    file_ctx.stmts.iter().any(|stmt| {
        let range = stmt.range();
        if range.start() <= import_end || range.start() >= at {
            return false;
        }
        let mut names = Vec::new();
        match stmt {
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    collect_target_names(target, &mut names);
                }
            }
            Stmt::AnnAssign(assign) => collect_target_names(&assign.target, &mut names),
            Stmt::For(for_stmt) => collect_target_names(&for_stmt.target, &mut names),
            _ => {}
        }
        names.iter().any(|name| name == bound)
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5915_flags_assertion_after_expected_exception() {
        let flagged = scan(concat!(
            "import pytest\n",
            "def test_case():\n",
            "    with pytest.raises(ValueError):\n",
            "        raise ValueError()\n",
            "        assert value == 42\n"
        ));
        assert_eq!(findings(&flagged, "python:S5915").len(), 1);
    }
}
