use crate::support::for_each_function_def;
use crate::support::for_each_stmt;
use crate::support::is_standalone_string_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtFunctionDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1720 — public definitions lacking a docstring ----------------------

pub(crate) fn check_missing_docstrings(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &std::path::Path,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    // Sonar's MissingDocstringCheck does not flag empty __init__.py
    // modules — the file itself is the package marker.
    let is_empty_init = path.file_name().and_then(|n| n.to_str()) == Some("__init__.py")
        && parsed.syntax().body.is_empty();
    if !is_empty_init
        && !parsed
            .syntax()
            .body
            .first()
            .is_some_and(is_standalone_string_stmt)
    {
        issues.push(Issue::new(
            "python:S1720",
            "Add a docstring to this module.",
            hoonarqube_ir::Range::file_level(),
        ));
    }
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::ClassDef(class) = stmt else {
            return;
        };
        if class.name.as_str().starts_with('_') {
            return;
        }
        if !class.body.first().is_some_and(is_standalone_string_stmt) {
            issues.push(issue_at(
                "python:S1720",
                "Add a docstring to this class.",
                class.name.range,
                index,
                source,
            ));
        }
    });
    let mut visit = |function: &StmtFunctionDef, in_class_body: bool| {
        if in_class_body {
            return;
        }
        // Sonar exempts only methods (class-body definitions); every
        // non-method function is flagged regardless of its name, including
        // module-level and nested dunder functions like `__getattr__`.
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
        assert_eq!(findings(&flagged, "python:S1720").len(), 3);
    }

    #[test]
    fn s1720_spares_private_and_documented_functions() {
        for clean in [
            // Dunder protocol methods are exempt; private functions are not.
            "\"\"\"Docs.\"\"\"\nclass C:\n    \"\"\"Docs.\"\"\"\n    def __init__(self):\n        self.x = 1\n",
            // A docstring fills the contract.
            "\"\"\"Docs.\"\"\"\ndef documented():\n    \"\"\"Docs.\"\"\"\n",
            "\"\"\"Docs.\"\"\"\nclass C:\n    \"\"\"Docs.\"\"\"\n    def method(self):\n        \"\"\"Docs.\"\"\"\n",
        ] {
            assert!(findings(&scan(clean), "python:S1720").is_empty());
        }
        // Private functions are flagged — Sonar does not exempt them.
        let private = "\"\"\"Docs.\"\"\"\ndef _helper():\n    return 1\n";
        assert_eq!(findings(&scan(private), "python:S1720").len(), 1);
    }

    #[test]
    fn s1720_flags_dunder_named_functions_outside_class_bodies() {
        // Sonar exempts only methods; module-level and nested dunder
        // functions still require a docstring (pinned Django sites:
        // __getattr__, __reduce__, __new__, __wrapper__).
        let source = concat!(
            "\"\"\"Docs.\"\"\"\n",
            "def __getattr__(name):\n",
            "    return name\n",
            "def outer():\n",
            "    \"\"\"Docs.\"\"\"\n",
            "    def __wrapper__(self, *args):\n",
            "        return args\n",
            "    return __wrapper__\n",
        );
        let report = scan(source);
        let hits = findings(&report, "python:S1720");
        assert_eq!(hits.len(), 2, "{source}");
        let lines: Vec<_> = hits.iter().map(|issue| issue.range.start.line).collect();
        assert_eq!(lines, vec![2, 6]);
    }

    #[test]
    fn s1720_class_after_function_inserts_into_class_body() {
        let source =
            "def previous():\n    return 1\nclass C(Base):\n    # class comment\n    value = 1\n";
        let report = scan(source);
        let issue = findings(&report, "python:S1720")
            .into_iter()
            .find(|issue| issue.message == "Add a docstring to this class.")
            .expect("class finding");
        let alternative = issue
            .alternatives
            .iter()
            .find(|alternative| alternative.id == "s1720-add-docstring")
            .expect("class docstring alternative");
        let edits = alternative.fix.edits.iter().collect::<Vec<_>>();
        let fixed = hoonarqube_ir::apply_fixes(source, &edits).expect("fix applies");
        assert_eq!(
            fixed,
            "def previous():\n    return 1\nclass C(Base):\n    # class comment\n    \"\"\" doc \"\"\"\n    value = 1\n"
        );
    }

    #[test]
    fn s1720_triple_quoted_class_base_keeps_ast_context() {
        let source =
            "def previous():\n    return 1\nclass C(\"\"\"base)): #\"\"\"):\n    value = 1\n";
        let report = scan(source);
        let issue = findings(&report, "python:S1720")
            .into_iter()
            .find(|issue| issue.message == "Add a docstring to this class.")
            .expect("class finding");
        let alternative = issue
            .alternatives
            .iter()
            .find(|alternative| alternative.id == "s1720-add-docstring")
            .expect("class docstring alternative");
        let edits = alternative.fix.edits.iter().collect::<Vec<_>>();
        let fixed = hoonarqube_ir::apply_fixes(source, &edits).expect("fix applies");
        assert_eq!(
            fixed,
            "def previous():\n    return 1\nclass C(\"\"\"base)): #\"\"\"):\n    \"\"\" doc \"\"\"\n    value = 1\n"
        );
    }

    #[test]
    fn s1720_inline_class_suite_stays_fixless() {
        let source = "def previous():\n    return 1\nclass Inline: pass\n";
        let report = scan(source);
        let issue = findings(&report, "python:S1720")
            .into_iter()
            .find(|issue| issue.message == "Add a docstring to this class.")
            .expect("class finding");
        assert!(
            issue.alternatives.is_empty(),
            "ambiguous inline class suite must not edit a prior function"
        );
    }
}
