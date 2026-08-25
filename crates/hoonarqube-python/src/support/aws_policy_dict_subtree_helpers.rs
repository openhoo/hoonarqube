// --- AWS policy-dict subtree helpers

use crate::support::{
    child_exprs, dict_string_entry, int_literal_value, is_true_literal, keyword_value,
    string_literal_text,
};
use ruff_python_ast::Expr;

fn call_subtree_dicts(call: &ruff_python_ast::ExprCall) -> Vec<&ruff_python_ast::ExprDict> {
    let mut found = Vec::new();
    let mut stack: Vec<&Expr> = call.arguments.args.iter().collect();
    stack.extend(call.arguments.keywords.iter().map(|keyword| &keyword.value));
    while let Some(expr) = stack.pop() {
        if let Expr::Dict(dict) = expr {
            found.push(dict);
        }
        stack.extend(child_exprs(expr));
    }
    found
}

/// Whether any call-subtree dict maps `key` to the given integer.
pub(crate) fn call_subtree_has_port(call: &ruff_python_ast::ExprCall, ports: &[i64]) -> bool {
    call_subtree_dicts(call).iter().any(|dict| {
        ["FromPort", "ToPort"].iter().any(|key| {
            dict_string_entry(dict, key)
                .and_then(int_literal_value)
                .is_some_and(|value| ports.contains(&value))
        })
    })
}

/// Whether any call-subtree dict maps `CidrIp` to `"0.0.0.0/0"`.
pub(crate) fn call_subtree_open_world(call: &ruff_python_ast::ExprCall) -> bool {
    call_subtree_dicts(call).iter().any(|dict| {
        dict_string_entry(dict, "CidrIp")
            .and_then(string_literal_text)
            .as_deref()
            == Some("0.0.0.0/0")
    })
}

/// Calls carrying `<name>=True` as a keyword or inside a subtree dict.
pub(crate) fn sets_true_flag(call: &ruff_python_ast::ExprCall, name: &str) -> bool {
    if keyword_value(&call.arguments, name).is_some_and(is_true_literal) {
        return true;
    }
    call_subtree_dicts(call)
        .iter()
        .any(|dict| dict_string_entry(dict, name).is_some_and(is_true_literal))
}
