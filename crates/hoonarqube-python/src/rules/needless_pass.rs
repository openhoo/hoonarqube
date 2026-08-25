use crate::engine::scope::SuiteOwner;
use crate::support::visit_suites_for_pass;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_needless_pass(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suites_for_pass(
        parsed.syntax().body.as_slice(),
        SuiteOwner::Module,
        &mut issues,
        index,
        source,
    );
    issues
}

// ---------------------------------------------------------------------------
// Tier-A battery entries #48–#110 (python:S2772 … python:S7512).
//
// One private check per catalog entry, wired through `check_tier_a_battery`.
// Detection follows the batch spec: single-file AST/token/text heuristics
// with deliberately conservative predicates.
#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2772_flags_only_redundant_pass() {
        let flagged = scan("def f():\n    pass\n    return 1\n");
        let found = findings(&flagged, "python:S2772");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        for clean in ["def f():\n    pass\n", "class A:\n    pass\n    x = 1\n"] {
            assert!(
                findings(&scan(clean), "python:S2772").is_empty(),
                "clean: {clean}"
            );
        }
    }
}
