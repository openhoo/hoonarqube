use crate::engine::file_context::FileContext;
use crate::support::dotted_name_is;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_json_response_safe_flag(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !dotted_name_is(&call.func, "JsonResponse") || has_keyword(&call.arguments, "safe") {
            continue;
        }
        let provably_non_dict = matches!(
            call.arguments.args.first(),
            Some(
                Expr::List(_)
                    | Expr::Set(_)
                    | Expr::Tuple(_)
                    | Expr::StringLiteral(_)
                    | Expr::NumberLiteral(_)
                    | Expr::BooleanLiteral(_)
                    | Expr::NoneLiteral(_)
            )
        );
        if provably_non_dict {
            issues.push(issue_at(
                "python:S6560",
                "Pass safe=False or serialize this payload into a dict.",
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
    fn s6560_requires_safe_flag_for_non_dict_payloads() {
        let flagged =
            scan("JsonResponse([1, 2])\nJsonResponse({\"a\": 1})\nJsonResponse([1], safe=False)\n");
        assert_eq!(findings(&flagged, "python:S6560").len(), 1);
    }
}
