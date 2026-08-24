use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::preferred_assertion;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_imprecise_assertions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if let Some(better) = preferred_assertion(call) {
            issues.push(issue_at(
                "python:S5906",
                &format!("Use {better} for this assertion."),
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5906_suggests_specific_assertions() {
        let flagged = scan(concat!(
            "case.assertEqual(x, True)\n",
            "case.assertTrue(x == y)\n",
            "case.assertFalse(a in b)\n",
            "case.assertEqual(x, y)\n"
        ));
        assert_eq!(findings(&flagged, "python:S5906").len(), 3);
    }
}
