use crate::support::for_each_function_def;
use crate::support::is_standalone_string_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::StmtFunctionDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1720 — public definitions lacking a docstring ----------------------

pub(crate) fn check_missing_docstrings(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut visit = |function: &StmtFunctionDef, _in_class_body: bool| {
        // Underscore-prefixed names are private by convention and exempt,
        // which also covers dunder protocol methods like `__init__`.
        if function.name.id.as_str().starts_with('_') {
            return;
        }
        let documented = function.body.first().is_some_and(is_standalone_string_stmt);
        if !documented {
            issues.push(issue_at(
                "python:S1720",
                "Add a docstring to this function.",
                function.name.range(),
                index,
                source,
            ));
        }
    };
    for_each_function_def(parsed.syntax().body.as_slice(), false, &mut visit);
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1720_flags_public_definitions_without_docstrings() {
        let flagged =
            scan("def bare():\n    return 1\nclass C:\n    def method(self):\n        return 2\n");
        assert_eq!(findings(&flagged, "python:S1720").len(), 2);
    }

    #[test]
    fn s1720_spares_private_and_documented_functions() {
        for clean in [
            // Underscore-prefixed names are private; dunders are exempt too.
            "def _helper():\n    return 1\nclass C:\n    def __init__(self):\n        self.x = 1\n",
            // A docstring fills the contract.
            "def documented():\n    \"\"\"Docs.\"\"\"\n",
            "class C:\n    def method(self):\n        \"\"\"Docs.\"\"\"\n",
        ] {
            assert!(findings(&scan(clean), "python:S1720").is_empty());
        }
    }
}
