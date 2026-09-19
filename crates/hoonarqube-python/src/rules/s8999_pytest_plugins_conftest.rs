use std::path::Path;

use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{for_each_stmt_in_scope, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8999";
const MESSAGE: &str = "\"pytest_plugins\" should be defined in conftest.py files";

/// python:S8999 — `pytest_plugins` declared in a test module registers plugins
/// only when that module is imported during collection, so plugin availability
/// depends on collection order; `conftest.py` loads before collection. The
/// reference check flags module-level `pytest_plugins` assignments (plain or
/// annotated with a value) in any file other than `conftest.py`; the target
/// name is the anchor. Assignments inside functions or classes, bare
/// annotations without a value, and `conftest.py` itself stay silent.
pub(crate) fn check_s8999_pytest_plugins_conftest(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    if path.file_name().and_then(|name| name.to_str()) == Some("conftest.py") {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_stmt_in_scope(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                flag_pytest_plugins_target(target, index, source, &mut issues);
            }
        }
        Stmt::AnnAssign(assign) => {
            if assign.value.is_some()
                && let Expr::Name(name) = assign.target.as_ref()
                && name.id.as_str() == "pytest_plugins"
            {
                issues.push(issue_at(RULE_KEY, MESSAGE, name.range(), index, source));
            }
        }
        _ => {}
    });
    issues
}

/// Flags the `pytest_plugins` name inside one assignment target: a bare name
/// or a direct element of a tuple/list unpacking target (the reference checks
/// the expression list's direct expressions, so `*rest` stays opaque).
fn flag_pytest_plugins_target(
    target: &Expr,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let elements: &[Expr] = match target {
        Expr::Name(name) => {
            if name.id.as_str() == "pytest_plugins" {
                issues.push(issue_at(RULE_KEY, MESSAGE, name.range(), index, source));
            }
            return;
        }
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::List(list) => &list.elts,
        _ => return,
    };
    for element in elements {
        if let Expr::Name(name) = element
            && name.id.as_str() == "pytest_plugins"
        {
            issues.push(issue_at(RULE_KEY, MESSAGE, name.range(), index, source));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{findings, pos, scan_at, scan_test_file};

    const KEY: &str = "python:S8999";

    #[test]
    fn s8999_flags_module_level_assignments() {
        let report = scan_test_file(
            "pytest_plugins = [\"pytest_cov\", \"pytest_timeout\"]\n\
             pytest_plugins: list[str] = [\"pytest_cov\"]\n\
             pytest_plugins: list[str]\n\
             \n\
             other_plugins = [\"pytest_cov\"]\n\
             \n\
             def test_feature():\n\
             \x20   assert other_plugins[0] == \"pytest_cov\"\n\
             \n\
             def nested():\n\
             \x20   pytest_plugins = [\"pytest_cov\"]\n\
             \n\
             class TestClass:\n\
             \x20   pytest_plugins = [\"pytest_cov\"]\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].range.start, pos(1, 0));
        assert_eq!(hits[0].range.end, pos(1, 14));
        assert_eq!(hits[1].range.start, pos(2, 0));
    }

    #[test]
    fn s8999_flags_tuple_and_chained_targets() {
        let report = scan_test_file(
            "pytest_plugins, other = [\"a\"], [\"b\"]\n\
             pytest_plugins = alias = [\"c\"]\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].range.start, pos(1, 0));
        assert_eq!(hits[1].range.start, pos(2, 0));
    }

    #[test]
    fn s8999_accepts_conftest_and_non_test_files() {
        let source = "pytest_plugins = [\"pytest_cov\"]\n";
        assert!(findings(&scan_at(PathBuf::from("conftest.py"), source), KEY).is_empty());
        // TEST scope in the reference: the check only runs on test files, but
        // hoonarqube TEST-scope rules are not file-gated; a main-scope file
        // with the same shape is still flagged.
        let main = scan_at(PathBuf::from("plugin_setup.py"), source);
        assert_eq!(findings(&main, KEY).len(), 1);
    }
}
