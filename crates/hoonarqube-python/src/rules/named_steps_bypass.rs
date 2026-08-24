use crate::support::collect_caching_pipeline_variables;
use crate::support::for_each_expr_in_module;
use crate::support::issue_at;
use crate::support::receiver_root;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_named_steps_bypass(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let pipelines = collect_caching_pipeline_variables(parsed.syntax().body.as_slice());
    let mut issues = Vec::new();
    for_each_expr_in_module(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Subscript(subscript) = expr
            && let Expr::Attribute(attribute) = subscript.value.as_ref()
            && attribute.attr.as_str() == "named_steps"
            && receiver_root(&attribute.value)
                .is_some_and(|root| pipelines.iter().any(|n| n == root))
        {
            issues.push(issue_at(
                "python:S6971",
                "Direct named_steps access bypasses this Pipeline's cache.",
                subscript.range(),
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
    fn s6971_flags_named_steps_bypass_on_cached_pipelines() {
        let flagged = scan(concat!(
            "pipe = Pipeline(steps, memory=\"./c\")\n",
            "step = pipe.named_steps[\"s\"]\n",
            "plain = other.named_steps[\"s\"]\n"
        ));
        assert_eq!(findings(&flagged, "python:S6971").len(), 1);
    }
}
