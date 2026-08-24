use crate::support::autoescape_off;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5247_autoescaping_disabled(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if autoescape_off(call) {
            issues.push(issue_at(
                "python:S5247",
                "Do not disable HTML auto-escaping in this template engine configuration.",
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
    fn s5247_flags_autoescaping_disabled_calls() {
        let flagged = concat!(
            "env = Environment(autoescape=False)\n",
            "sa = select_autoescape(enabled=False)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S5247").len(), 2);
        let clean = concat!(
            "env = Environment(autoescape=True)\n",
            "env2 = Environment(loader=loader)\n"
        );
        assert!(findings(&scan(clean), "python:S5247").is_empty());
    }
}
