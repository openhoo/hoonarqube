use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5247_autoescaping_disabled(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if autoescape_off(call) {
            issues.push(issue_at(
                "python:S5247",
                "Do not disable HTML auto-escaping in this template engine configuration.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S5247 / S5439 — HTML autoescaping disabled ------------------------

/// Jinja shapes that switch autoescaping off.
pub(crate) fn autoescape_off(call: &ruff_python_ast::ExprCall) -> bool {
    const AUTOESCAPE_ENGINES: [&str; 2] = ["Environment", "select_autoescape"];
    AUTOESCAPE_ENGINES.contains(&called_name(&call.func).unwrap_or_default())
        && (keyword_value(&call.arguments, "autoescape").is_some_and(is_false_literal)
            || keyword_value(&call.arguments, "enabled").is_some_and(is_false_literal))
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
