use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::matches_snake_case;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// Methods (functions declared directly in a class body) are python:S100;
/// module-level and nested functions are python:S1542.
pub(crate) fn check_method_and_function_names(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, in_class_body| {
            if !matches_snake_case(function.name.as_str()) {
                let (rule_key, kind) = if in_class_body {
                    ("python:S100", "method")
                } else {
                    ("python:S1542", "function")
                };
                issues.push(issue_at(
                    rule_key,
                    &format!(
                        "Rename {kind} \"{}\" to match the regular expression ^[a-z_][a-z0-9_]*$.",
                        function.name
                    ),
                    function.name.range(),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}

// ---------------------------------------------------------------------------
// Tier A — naming conventions (python:S100, python:S101, python:S116,
// python:S117, python:S1542).

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s100_flags_non_snake_case_methods() {
        let flagged = scan("class Service:\n    def Load(self):\n        pass\n");
        let found = findings(&flagged, "python:S100");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        assert!(findings(&flagged, "python:S1542").is_empty());
    }

    #[test]
    fn s1542_flags_module_level_functions_only() {
        let flagged = scan("def Compute(value):\n    return value * 2\n");
        assert_eq!(findings(&flagged, "python:S1542").len(), 1);
        assert!(findings(&flagged, "python:S100").is_empty());
    }

    #[test]
    fn snake_case_boundaries_split_clean_from_flagged() {
        for clean in [
            "def sha256(data):\n    return data\n",
            "class C:\n    def _helper(self):\n        pass\n",
        ] {
            let report = scan(clean);
            assert!(
                findings(&report, "python:S100").is_empty()
                    && findings(&report, "python:S1542").is_empty(),
                "{clean}"
            );
        }

        let non_ascii = scan("def café():\n    pass\n");
        assert_eq!(findings(&non_ascii, "python:S1542").len(), 1);
    }
}
