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
    report_on_strings: bool,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suites_for_no_effect(
        parsed.syntax().body.as_slice(),
        &mut issues,
        index,
        source,
        report_on_strings,
    );
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

    #[test]
    fn s905_protocol_ellipsis_stubs_and_attribute_docstrings_are_clean() {
        // Issue #119: valid Protocol stub bodies and attribute documentation
        // strings are not no-effect statements under reportOnStrings=false.
        let clean = scan(concat!(
            "from typing import Protocol\n",
            "class P(Protocol):\n",
            "    def method(self) -> None: ...\n",
            "class C:\n",
            "    value = 1\n",
            "    \"\"\"Documentation for value.\"\"\"\n",
        ));
        assert!(findings(&clean, "python:S905").is_empty());
    }

    #[test]
    fn s905_overload_ellipsis_bodies_are_clean() {
        let clean = scan(concat!(
            "from typing import overload\n",
            "@overload\n",
            "def parse(value: int) -> int: ...\n",
            "@overload\n",
            "def parse(value: str) -> str: ...\n",
            "def parse(value):\n",
            "    return value\n",
        ));
        assert!(findings(&clean, "python:S905").is_empty());
    }

    #[test]
    fn s905_still_reports_genuinely_effectless_statements() {
        // Module-level ellipsis and pure literals stay reported; only
        // declaration-position stubs and strings are exempt.
        let flagged = scan("\"\"\"Module doc.\"\"\"\n...\n42\n");
        let found = findings(&flagged, "python:S905");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[1].range.start.line, 3);
    }
}
