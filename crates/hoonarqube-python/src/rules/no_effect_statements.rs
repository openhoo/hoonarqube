use crate::support::visit_suites_for_no_effect;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S905 — statements without effect ----------------------------------

pub(crate) fn check_no_effect_statements(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suites_for_no_effect(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s905_flags_pure_expression_statements_but_not_docstrings() {
        let flagged = scan("\"\"\"Module doc.\"\"\"\n42\nx == 1\nrun(x)\n");
        let found = findings(&flagged, "python:S905");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[1].range.start.line, 3);
    }
}
