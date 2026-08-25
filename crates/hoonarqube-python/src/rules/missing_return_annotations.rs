use crate::AnalyzerOptions;
use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6538 / python:S6540 — missing annotations (opt-in) -----------------

pub(crate) fn check_missing_return_annotations(
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !options.require_type_hints {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt
            && function.returns.is_none()
        {
            issues.push(issue_at(
                "python:S6538",
                "Add a return type annotation to this function.",
                function.name.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::{findings, scan};
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn s6538_gated_return_annotations() {
        let source = "def add(a, b):\n    return a\n";
        assert!(findings(&scan(source), "python:S6538").is_empty());
        let options = AnalyzerOptions {
            require_type_hints: true,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), source, &options);
        assert_eq!(findings(&report, "python:S6538").len(), 1);
    }
}
