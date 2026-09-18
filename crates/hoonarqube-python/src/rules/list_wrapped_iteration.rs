use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Comprehension, Expr, ExprCall, Stmt, StmtFor};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7504 — list() when iterating ---------------------------------------

/// Mutating methods Sonar's `UnnecessaryListCastCheck` counts for a bare
/// `list(name)` argument (`modifyingListMethodMatcher`).
const MUTATING_LIST_METHODS: &[&str] = &[
    "append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse",
];
/// Mutating methods Sonar counts for a `list(d.keys())`/`list(d.items())`
/// argument (`modifyingDictMethodMatcher`).
const MUTATING_DICT_METHODS: &[&str] = &["pop", "popitem", "clear", "update", "setdefault"];

pub(crate) fn check_list_wrapped_iteration(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::For(for_stmt) = stmt
            && let Expr::Call(call) = for_stmt.iter.as_ref()
            && is_builtin_list_call(call)
            && !collection_mutated_in_loop(for_stmt, call)
        {
            issues.push(s7504_issue(call, index, source));
        }
    }
    // Sonar also subscribes to comprehension `for` clauses and reports them
    // unconditionally: a comprehension cannot mutate its iterable
    // mid-iteration, so the exemption never applies there.
    for &expr in &file_ctx.exprs {
        let generators: &[Comprehension] = match expr {
            Expr::ListComp(e) => &e.generators,
            Expr::SetComp(e) => &e.generators,
            Expr::DictComp(e) => &e.generators,
            Expr::Generator(e) => &e.generators,
            _ => continue,
        };
        for generator in generators {
            if let Expr::Call(call) = &generator.iter
                && is_builtin_list_call(call)
            {
                issues.push(s7504_issue(call, index, source));
            }
        }
    }
    issues
}

fn s7504_issue(call: &ExprCall, index: &LineIndex, source: &str) -> Issue {
    issue_at(
        "python:S7504",
        "Iterate over the iterable directly; wrapping it in 'list()' is unnecessary.",
        call.range(),
        index,
        source,
    )
}

/// Only the bare `list(...)` builtin — `finder.list(...)` is a method call,
/// not a cast.
fn is_builtin_list_call(call: &ExprCall) -> bool {
    matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "list")
}

/// Sonar exempts `for x in list(c)` when the loop mutates `c` — the copy is
/// intentional. A bare `list(name)` argument exempts on list-mutating method
/// calls; a `list(d.keys())`/`list(d.items())` argument exempts on
/// dict-mutating method calls and `del d[k]`/`d[k] = v` subscript writes.
/// `list(d.values())` is never exempt: Sonar's dict-view matcher covers
/// `keys()` and `items()` only.
fn collection_mutated_in_loop(for_stmt: &StmtFor, call: &ExprCall) -> bool {
    let Some(arg) = sole_positional_arg(call) else {
        return false;
    };
    match arg {
        Expr::Name(collection) => loop_mutates_collection(
            for_stmt,
            collection.id.as_str(),
            MUTATING_LIST_METHODS,
            false,
        ),
        Expr::Call(view) => {
            let Expr::Attribute(view_attr) = view.func.as_ref() else {
                return false;
            };
            if !matches!(view_attr.attr.as_str(), "keys" | "items") {
                return false;
            }
            let Expr::Name(collection) = view_attr.value.as_ref() else {
                return false;
            };
            loop_mutates_collection(
                for_stmt,
                collection.id.as_str(),
                MUTATING_DICT_METHODS,
                true,
            )
        }
        _ => false,
    }
}

/// The single positional argument of `list(x)` — keyword or extra arguments
/// never reach the exemption.
fn sole_positional_arg(call: &ExprCall) -> Option<&Expr> {
    let arguments = &call.arguments;
    if arguments.args.len() == 1 && arguments.keywords.is_empty() {
        arguments.args.first()
    } else {
        None
    }
}

/// Mirrors Sonar's `ModifyingCollectionTreeVisitor` over the whole `for`
/// statement: mutating method calls anywhere (header expressions included),
/// plus — for dict receivers only — `del d[k]` and `d[k] = v` subscript
/// writes.
fn loop_mutates_collection(
    for_stmt: &StmtFor,
    collection: &str,
    methods: &[&str],
    subscripts_count: bool,
) -> bool {
    let mut mutated = false;
    let mut visit = |stmt: &Stmt| {
        mutated |= subscripts_count && stmt_mutates_collection(stmt, collection);
        crate::support::for_each_stmt_expr(std::slice::from_ref(stmt), &mut |expr| {
            mutated |= mutating_method_call(expr, collection, methods);
        });
    };
    crate::support::for_each_stmt(&for_stmt.body, &mut visit);
    crate::support::for_each_stmt(&for_stmt.orelse, &mut visit);
    // Sonar's visitor also sees the loop header expressions.
    let mut check_header = |expr: &Expr| {
        mutated |= mutating_method_call(expr, collection, methods);
    };
    crate::support::for_each_expr(for_stmt.iter.as_ref(), &mut check_header);
    crate::support::for_each_expr(for_stmt.target.as_ref(), &mut check_header);
    mutated
}

/// `del d[k]` or `d[k] = v` inside the loop — counted for dict-view
/// arguments only.
fn stmt_mutates_collection(stmt: &Stmt, collection: &str) -> bool {
    match stmt {
        Stmt::Delete(del) => del
            .targets
            .iter()
            .any(|target| subscript_of(target, collection)),
        Stmt::Assign(assign) => assign
            .targets
            .iter()
            .any(|target| assignment_target_mutates(target, collection)),
        _ => false,
    }
}

/// `name.method(...)` where `method` is in the mutating set.
fn mutating_method_call(expr: &Expr, collection: &str, methods: &[&str]) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    let Expr::Attribute(attr) = call.func.as_ref() else {
        return false;
    };
    methods.contains(&attr.attr.as_str())
        && matches!(attr.value.as_ref(), Expr::Name(n) if n.id.as_str() == collection)
}

/// `name[...]` — a subscript write target on the collection.
fn subscript_of(expr: &Expr, collection: &str) -> bool {
    matches!(
        expr,
        Expr::Subscript(sub) if matches!(sub.value.as_ref(), Expr::Name(n) if n.id.as_str() == collection)
    )
}

/// Sonar flattens assignment LHS expression lists: `d[k], x = v` still
/// counts as a subscript write on `d`.
fn assignment_target_mutates(expr: &Expr, collection: &str) -> bool {
    match expr {
        Expr::Tuple(tuple) => tuple.elts.iter().any(|elt| subscript_of(elt, collection)),
        _ => subscript_of(expr, collection),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const RULE: &str = "python:S7504";

    #[test]
    fn s7504_ignores_attribute_list_method_calls() {
        // Issue #648: `finder.list(patterns)` is a method call, not the
        // builtin — pinned from django collectstatic.py.
        let report = scan(concat!(
            "def collect(finder, patterns):\n",
            "    for path, storage in finder.list(patterns):\n",
            "        print(path)\n",
        ));
        assert!(findings(&report, RULE).is_empty());
    }

    #[test]
    fn s7504_exempts_dict_view_copy_when_loop_mutates_dict() {
        // Issue #648: `list(body.items())` is an intentional copy when the
        // loop deletes keys — pinned from django sqlite3 schema.py.
        let report = scan(concat!(
            "def fix(body):\n",
            "    for name, field in list(body.items()):\n",
            "        if field.bad:\n",
            "            del body[name]\n",
        ));
        assert!(findings(&report, RULE).is_empty());
    }

    #[test]
    fn s7504_exempts_list_copy_when_loop_mutates_list() {
        // Sonar's exemption also covers a bare `list(name)` argument when
        // the loop calls list-mutating methods on `name`.
        let report = scan(concat!(
            "def drain(queue):\n",
            "    for item in list(queue):\n",
            "        queue.pop()\n",
        ));
        assert!(findings(&report, RULE).is_empty());
    }

    #[test]
    fn s7504_flags_list_wrap_without_mutation() {
        let report = scan(concat!(
            "def show(items):\n",
            "    for item in list(items):\n",
            "        print(item)\n",
        ));
        assert_eq!(findings(&report, RULE).len(), 1);
    }

    #[test]
    fn s7504_flags_dict_view_wrap_without_mutation() {
        let report = scan(concat!(
            "def show(body):\n",
            "    for name, field in list(body.items()):\n",
            "        print(name)\n",
        ));
        assert_eq!(findings(&report, RULE).len(), 1);
    }

    #[test]
    fn s7504_flags_values_view_even_when_loop_mutates_dict() {
        // Sonar's dict-view matcher is keys()/items() only — `values()` is
        // not exempted even when the loop mutates the dict.
        let report = scan(concat!(
            "def fix(body):\n",
            "    for field in list(body.values()):\n",
            "        if field.bad:\n",
            "            del body[field.name]\n",
        ));
        assert_eq!(findings(&report, RULE).len(), 1);
    }

    #[test]
    fn s7504_flags_bare_name_wrap_despite_subscript_writes() {
        // Sonar only counts `del d[k]`/`d[k] = v` for dict-view arguments;
        // a bare `list(d)` argument exempts on list-mutating methods alone.
        for source in [
            "def fix(d):\n    for key in list(d):\n        d[key] = 0\n",
            "def fix(d):\n    for key in list(d):\n        del d[key]\n",
        ] {
            assert_eq!(findings(&scan(source), RULE).len(), 1, "{source}");
        }
    }

    #[test]
    fn s7504_flags_list_wrap_in_comprehensions() {
        // Sonar checks comprehension `for` clauses unconditionally — pinned
        // from django forms.py `list(attrs.items())` inside a dict comp.
        for source in [
            "d = {k: v for k, v in list(attrs.items())}\n",
            "d = [x for x in list(items)]\n",
            "d = {x for x in list(items)}\n",
            "d = (x for x in list(items))\n",
        ] {
            assert_eq!(findings(&scan(source), RULE).len(), 1, "{source}");
        }
    }

    #[test]
    fn s7504_ignores_plain_iterable_comprehensions() {
        let report = scan("d = {k: v for k, v in attrs.items()}\n");
        assert!(findings(&report, RULE).is_empty());
    }
}
