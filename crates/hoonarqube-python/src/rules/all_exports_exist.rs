use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::support::child_bodies;
use crate::support::issue_at;
use crate::support::module_all_exports;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S5807 — __all__ names must exist ---------------------------------

pub(crate) fn check_all_exports_exist(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    // Sonar's UndefinedNameAllPropertyCheck exempts modules defining
    // module-level __getattr__ or __dir__ — they resolve __all__ entries
    // dynamically.
    if facts.dynamic_names
        || facts.has_wildcard_import
        || module_defines_dynamic_lookup(&parsed.syntax().body)
    {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for (exported, range) in module_all_exports(parsed) {
        if !table.scopes[0].bindings.contains_key(&exported) {
            issues.push(issue_at(
                "python:S5807",
                &format!("Change or remove this string; \"{exported}\" is not defined."),
                range,
                index,
                source,
            ));
        }
    }
    issues
}

/// Whether the module defines `__getattr__` or `__dir__` at module level.
/// Mirrors Sonar's `ModuleLevelVisitor`: descends through compound
/// statements (`if`/`try`/`with`/loops/`match`) but never into function or
/// class bodies.
fn module_defines_dynamic_lookup(stmts: &[Stmt]) -> bool {
    let mut pending: Vec<&Stmt> = stmts.iter().collect();
    while let Some(stmt) = pending.pop() {
        match stmt {
            Stmt::FunctionDef(function) => {
                if matches!(function.name.as_str(), "__getattr__" | "__dir__") {
                    return true;
                }
            }
            Stmt::ClassDef(_) => {}
            _ => pending.extend(child_bodies(stmt).iter().flat_map(|body| body.iter())),
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5807_exempts_module_level_getattr_and_dir() {
        // Issue #624: a module-level __getattr__ resolves __all__ entries
        // dynamically (PEP 562), so Sonar reports nothing.
        let getattr = scan(concat!(
            "__all__ = [\"BadHeaderError\", \"send_mail\"]\n",
            "def __getattr__(name):\n",
            "    return _mod[name]\n"
        ));
        assert!(findings(&getattr, "python:S5807").is_empty());

        let dir = scan(concat!(
            "__all__ = [\"dynamic_name\"]\n",
            "def __dir__():\n",
            "    return [\"dynamic_name\"]\n"
        ));
        assert!(findings(&dir, "python:S5807").is_empty());
    }

    #[test]
    fn s5807_exemption_descends_module_blocks_but_not_class_or_function() {
        // Sonar's ModuleLevelVisitor descends through compound statements:
        // a __getattr__ inside a top-level if/try still exempts the module.
        let in_if = scan(concat!(
            "__all__ = [\"lazy_name\"]\n",
            "if True:\n",
            "    def __getattr__(name):\n",
            "        return _mod[name]\n"
        ));
        assert!(findings(&in_if, "python:S5807").is_empty());

        let in_try = scan(concat!(
            "__all__ = [\"lazy_name\"]\n",
            "try:\n",
            "    def __getattr__(name):\n",
            "        return _mod[name]\n",
            "except ImportError:\n",
            "    pass\n"
        ));
        assert!(findings(&in_try, "python:S5807").is_empty());

        // ...but it never enters class or function bodies, so these do not
        // exempt the module and the missing export is still flagged.
        let class_method = scan(concat!(
            "__all__ = [\"missing_one\"]\n",
            "class Lazy:\n",
            "    def __getattr__(self, name):\n",
            "        return None\n"
        ));
        let found = findings(&class_method, "python:S5807");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);

        let nested_function = scan(concat!(
            "__all__ = [\"missing_one\"]\n",
            "def outer():\n",
            "    def __getattr__(name):\n",
            "        return None\n"
        ));
        assert_eq!(findings(&nested_function, "python:S5807").len(), 1);
    }
}
