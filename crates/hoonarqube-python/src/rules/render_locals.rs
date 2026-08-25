use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::is_locals_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_render_locals(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name(&call.func).as_deref() == Some("render")
            && call.arguments.args.iter().any(is_locals_call)
        {
            issues.push(issue_at(
                "python:S6556",
                "Do not pass locals() to render.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6556_rejects_locals_in_render() {
        let flagged = scan("render(req, \"t.html\", locals())\nrender(req, \"t.html\", {})\n");
        assert_eq!(findings(&flagged, "python:S6556").len(), 1);
    }
}
