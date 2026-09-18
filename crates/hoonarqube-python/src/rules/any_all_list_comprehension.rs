use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7492 — materialized list passed to any/all -----------------------------

pub(crate) fn check_any_all_list_comprehension(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name_in(&call.func, &["any", "all"])
            && let [only] = &call.arguments.args[..]
            && matches!(only, Expr::ListComp(_))
        {
            issues.push(issue_at(
                "python:S7492",
                "Pass a generator expression instead of a materialized list.",
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

    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s7492_prefers_generator_expressions_for_any_all() {
        let flagged = scan("any([x for x in xs])\nany(x for x in xs)\n");
        assert_eq!(findings(&flagged, "python:S7492").len(), 1);
    }

    // python:S7492 anchors on the enclosing `any(`/`all(` call, not on the
    // list-comprehension argument (SonarQube 26.8 semantics, issue #674).
    #[test]
    fn s7492_anchors_on_the_call_expression() {
        let source = "    forms_valid = all(\n        [\n            form.is_valid()\n            for form in self.forms\n            if not (self.can_delete and self._should_delete_form(form))\n        ]\n    )\n";
        let report = scan(source);
        let found = findings(&report, "python:S7492");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start, pos(1, 18));
        assert_eq!(found[0].range.end, pos(7, 5));

        let single_line_report =
            scan("    return all([formset.is_valid() for formset in formsets])\n");
        let single_line = findings(&single_line_report, "python:S7492");
        assert_eq!(single_line.len(), 1);
        assert_eq!(single_line[0].range.start, pos(1, 11));
        assert_eq!(single_line[0].range.end, pos(1, 60));
    }
}
