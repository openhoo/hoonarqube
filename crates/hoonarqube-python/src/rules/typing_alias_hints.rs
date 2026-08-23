use crate::support::dotted_name;
use crate::support::for_each_annotation;
use crate::support::for_each_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_typing_alias_hints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const TYPING_ALIASES: [&str; 12] = [
        "typing.List",
        "typing.Dict",
        "typing.Set",
        "typing.Tuple",
        "typing.FrozenSet",
        "typing.Type",
        "List",
        "Dict",
        "Set",
        "Tuple",
        "FrozenSet",
        "Type",
    ];
    let mut issues = Vec::new();
    for_each_annotation(parsed.syntax().body.as_slice(), &mut |annotation| {
        for_each_expr(annotation, &mut |expr| {
            if dotted_name(expr).is_some_and(|path| TYPING_ALIASES.contains(&path.as_str())) {
                issues.push(issue_at(
                    "python:S6545",
                    "Use builtin generics instead of the typing alias.",
                    expr.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}
