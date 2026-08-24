use crate::support::for_each_stmt;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_methods_missing_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if !has_decorator(function, "staticmethod")
            && positional_parameters(&function.parameters).is_empty()
        {
            issues.push(issue_at(
                "python:S5719",
                "Add the missing instance or class method parameter ('self' or 'cls').",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S5719) ---
// --- python:S5719 — instance/class methods need a positional parameter --------

/// Iterates `(class, function)` for every method directly defined in a class
/// body anywhere in the tree.
pub(crate) fn for_each_method(
    stmts: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtClassDef, &ruff_python_ast::StmtFunctionDef),
) {
    for_each_stmt(stmts, &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            for member in &class.body {
                if let Stmt::FunctionDef(function) = member {
                    visit(class, function);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5719_requires_positional_parameter_on_methods() {
        let flagged = scan("class C:\n    def method():\n        return 1\n");
        assert_eq!(findings(&flagged, "python:S5719").len(), 1);
        let static_clean = "class C:\n    @staticmethod\n    def util():\n        return 1\n";
        assert!(findings(&scan(static_clean), "python:S5719").is_empty());
        let bound_clean = "class C:\n    def method(self):\n        return 1\n";
        assert!(findings(&scan(bound_clean), "python:S5719").is_empty());
    }

    #[test]
    fn s5719_flags_classmethod_vararg_only_and_kwonly_only() {
        let classmethod =
            scan("class C:\n    @classmethod\n    def create():\n        return C()\n");
        assert_eq!(findings(&classmethod, "python:S5719").len(), 1);

        let vararg_only = scan("class C:\n    def forward(*args):\n        pass\n");
        assert_eq!(findings(&vararg_only, "python:S5719").len(), 1);

        let kwonly_only = scan("class C:\n    def configure(*, key):\n        pass\n");
        assert_eq!(findings(&kwonly_only, "python:S5719").len(), 1);
    }

    #[test]
    fn s5719_ignores_module_level_functions() {
        let free_function = scan("def helper():\n    return 1\n");
        assert!(findings(&free_function, "python:S5719").is_empty());
    }
}
