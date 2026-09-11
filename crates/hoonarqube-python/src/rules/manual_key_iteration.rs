use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// --- python:S7517 — manual key/value iteration ------------------------------------

pub(crate) fn check_manual_key_iteration(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::For(for_stmt) = stmt else { continue };
        if two_plain_names(for_stmt.target.as_ref())
            && proven_dict_iterable(for_stmt.iter.as_ref(), for_stmt.range(), file_ctx)
        {
            issues.push(issue_at(
                "python:S7517",
                "Use '.items()' instead of iterating over dictionary keys and values separately.",
                for_stmt.iter.range(),
                index,
                source,
            ));
        }
    }
    for expr in &file_ctx.exprs {
        let generators = match expr {
            Expr::ListComp(comp) => &comp.generators,
            Expr::SetComp(comp) => &comp.generators,
            Expr::DictComp(comp) => &comp.generators,
            Expr::Generator(comp) => &comp.generators,
            _ => continue,
        };
        for generator in generators {
            if two_plain_names(&generator.target)
                && proven_dict_iterable(&generator.iter, expr.range(), file_ctx)
            {
                issues.push(issue_at(
                    "python:S7517",
                    "Use '.items()' instead of iterating over dictionary keys and values separately.",
                    generator.iter.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

fn two_plain_names(target: &Expr) -> bool {
    let elements = match target {
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::List(list) => &list.elts,
        _ => return false,
    };
    matches!(elements.as_slice(), [Expr::Name(_), Expr::Name(_)])
}

fn proven_dict_iterable(iterable: &Expr, owner: TextRange, file_ctx: &FileContext) -> bool {
    let Expr::Name(iterable) = iterable else {
        return false;
    };
    let enclosing_scope = file_ctx
        .functions
        .iter()
        .map(Ranged::range)
        .chain(file_ctx.classes.iter().map(Ranged::range))
        .filter(|scope| scope.contains_range(owner))
        .min_by_key(|scope| scope.end().to_u32() - scope.start().to_u32());
    let mut latest_binding: Option<&Stmt> = None;
    for candidate in &file_ctx.stmts {
        if candidate.range().start() >= owner.start() {
            continue;
        }
        let same_scope = match enclosing_scope {
            Some(scope) => scope.contains_range(candidate.range()),
            None => !file_ctx
                .functions
                .iter()
                .map(Ranged::range)
                .chain(file_ctx.classes.iter().map(Ranged::range))
                .any(|scope| scope.contains_range(candidate.range())),
        };
        if !same_scope {
            continue;
        }
        let binds_iterable = match candidate {
            Stmt::Assign(assign) => assign
                .targets
                .iter()
                .any(|target| matches!(target, Expr::Name(name) if name.id == iterable.id)),
            Stmt::AnnAssign(assign) => {
                matches!(assign.target.as_ref(), Expr::Name(name) if name.id == iterable.id)
            }
            _ => false,
        };
        if binds_iterable
            && latest_binding
                .is_none_or(|previous| previous.range().start() < candidate.range().start())
        {
            latest_binding = Some(*candidate);
        }
    }
    latest_binding.is_some_and(|candidate| match candidate {
        Stmt::Assign(assign) => matches!(assign.value.as_ref(), Expr::Dict(_)),
        Stmt::AnnAssign(assign) => assign
            .value
            .as_ref()
            .is_some_and(|value| matches!(value.as_ref(), Expr::Dict(_))),
        _ => false,
    })
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7517_flags_two_name_iteration_over_a_dict() {
        let flagged =
            scan("settings = {1: 2}\nfor key, value in settings:\n    print(key, value)\n");
        let found = findings(&flagged, "python:S7517");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[0].range.end.line, 2);

        let comprehension =
            scan("settings = {1: 2}\nresult = [(key, value) for key, value in settings]\n");
        assert_eq!(findings(&comprehension, "python:S7517").len(), 1);
    }

    #[test]
    fn s7517_stays_clean_without_two_names_and_a_proven_dict() {
        for clean in [
            "settings = {1: 2}\nfor key in settings:\n    print(settings[key])\n",
            "for key, value in settings:\n    print(key, value)\n",
            "settings = []\nfor key, value in settings:\n    print(key, value)\n",
            "settings = {1: 2}\nfor key, *values in settings:\n    print(key, values)\n",
            "settings = {1: 2}\nresult = [(key, value) for key in settings]\n",
            "settings = {1: 2}\nresult = [(key, value) for key, value in settings.items()]\n",
        ] {
            assert!(findings(&scan(clean), "python:S7517").is_empty(), "{clean}");
        }
    }
}
