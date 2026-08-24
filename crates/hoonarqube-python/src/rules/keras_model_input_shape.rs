use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::for_each_expr;
use crate::support::for_each_method;
use crate::support::for_each_stmt_in_scope;
use crate::support::has_keyword;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_keras_model_input_shape(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |class, function| {
        let model_subclass = class_base_paths(class)
            .iter()
            .any(|base| base_tail_is(base, "Model"));
        if !model_subclass || function.name.as_str() != "__init__" {
            return;
        }
        for_each_stmt_in_scope(function.body.as_slice(), &mut |stmt| {
            for expr in stmt_exprs(stmt) {
                for_each_expr(expr, &mut |expr| {
                    if let Expr::Call(call) = expr
                        && is_super_init_call(expr)
                        && has_keyword(&call.arguments, "input_shape")
                    {
                        issues.push(issue_at(
                            "python:S6919",
                            "Remove input_shape from super().__init__; subclasses infer shapes.",
                            expr.range(),
                            index,
                            source,
                        ));
                    }
                });
            }
        });
    });
    issues
}

// --- migrated from support/mod.rs (S6919) ---
// --- python:S6919 / python:S6974 — Keras Model / BaseEstimator subclass contracts ----

pub(crate) fn class_base_paths(class: &ruff_python_ast::StmtClassDef) -> Vec<String> {
    class
        .arguments
        .as_ref()
        .map(|arguments| arguments.args.iter().filter_map(dotted_name).collect())
        .unwrap_or_default()
}

pub(crate) fn base_tail_is(path: &str, tail: &str) -> bool {
    path.rsplit('.').next() == Some(tail)
}

pub(crate) fn is_super_init_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if matches!(call.func.as_ref(), Expr::Attribute(attr)
            if attr.attr.as_str() == "__init__"
                && matches!(attr.value.as_ref(), Expr::Call(outer)
                    if called_name(&outer.func) == Some("super"))))
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6919_rejects_input_shape_on_model_subclasses() {
        let flagged = scan(concat!(
            "class Net(keras.Model):\n",
            "    def __init__(self):\n",
            "        super().__init__(input_shape=(28,))\n",
            "class Fine(keras.Model):\n",
            "    def __init__(self):\n",
            "        super().__init__()\n"
        ));
        assert_eq!(findings(&flagged, "python:S6919").len(), 1);
    }
}
