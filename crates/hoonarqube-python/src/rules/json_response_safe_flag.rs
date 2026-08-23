use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_json_response_safe_flag(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if dotted_name(&call.func).as_deref() != Some("JsonResponse")
            || has_keyword(&call.arguments, "safe")
        {
            return;
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
    });
    issues
}
