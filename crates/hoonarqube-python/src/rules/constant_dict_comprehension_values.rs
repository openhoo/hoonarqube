use crate::engine::file_context::FileContext;
use crate::support::for_each_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::InterpolatedStringElement;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_constant_dict_comprehension_values(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::DictComp(comp) = expr
            && matches!(comp.key.as_ref(), Expr::Name(_))
            && let [generator] = comp.generators.as_slice()
            && generator.ifs.is_empty()
            && !generator.is_async
            && is_shared_value(&comp.value, &generator.target)
        {
            issues.push(issue_at(
                "python:S7506",
                "Use 'dict.fromkeys' to build a mapping with a constant value.",
                comp.value.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// A fromkeys value is reused, not evaluated afresh for every generated key.
/// Accept the reference's literal/name shapes, not recursively constant trees:
/// even a literal list would change from independent objects to one shared list.
fn is_shared_value(value: &Expr, target: &Expr) -> bool {
    match value {
        Expr::NoneLiteral(_)
        | Expr::BooleanLiteral(_)
        | Expr::NumberLiteral(_)
        | Expr::StringLiteral(_)
        | Expr::BytesLiteral(_) => true,
        Expr::FString(string) => string
            .value
            .elements()
            .all(|element| matches!(element, InterpolatedStringElement::Literal(_))),
        Expr::Name(value) => {
            let mut bound_by_generator = false;
            for_each_expr(target, &mut |node| {
                if let Expr::Name(name) = node {
                    bound_by_generator |= name.id == value.id;
                }
            });
            !bound_by_generator
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s7506_preserves_filtered_and_nested_comprehensions() {
        for source in [
            "field_names = {f: False for f in fields if not hasattr(f, 'resolve_expression')}\n",
            "result = {k: 0 for k in keys if k}\n",
            "result = {k: 0 for group in groups for k in group}\n",
            "async def collect(keys):\n    return {k: 0 async for k in keys}\n",
        ] {
            assert!(findings(&scan(source), "python:S7506").is_empty(), "{source}");
        }
    }

    #[test]
    fn s7506_rejects_ineligible_key_and_value_shapes() {
        for source in [
            "result = {k.name: 0 for k in keys}\n",
            "result = {k + 1: 0 for k in keys}\n",
            "result = {k: [] for k in keys}\n",
            "result = {k: {0} for k in keys}\n",
            "result = {k: (0,) for k in keys}\n",
            "result = {k: 1 + 2 for k in keys}\n",
            "result = {k: -1 for k in keys}\n",
            "result = {k: ... for k in keys}\n",
            "result = {k: factory() for k in keys}\n",
            "result = {k: f'{k}' for k in keys}\n",
            "result = {k: k for k in keys}\n",
            "result = {k: value for k, value in pairs}\n",
        ] {
            assert!(findings(&scan(source), "python:S7506").is_empty(), "{source}");
        }
    }

    #[test]
    fn s7506_preserves_genuine_fromkeys_suggestions() {
        for value in ["0", "False", "None", "'ready'", "b'ready'", "f'ready'", "shared"] {
            let source = format!("shared = object()\nresult = {{k: {value} for k in keys}}\n");
            let report = scan(&source);
            let issues = findings(&report, "python:S7506");
            assert_eq!(issues.len(), 1, "{source}");
            assert_eq!(issues[0].range.start, pos(2, 14), "{source}");
            assert_eq!(issues[0].range.end, pos(2, 14 + value.len() as u32), "{source}");
        }
    }
}
