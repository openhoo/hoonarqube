// Rule module s6302_all_privileges.
use super::shared::{
    CdkFile, EffectState, PolicyStyle, PropsView, policy_effect, policy_statements_call,
    policy_statements_new, property_value, wildcard_span,
};
use crate::support::IssueSink;
use crate::support::RuleScope;
use oxc_ast::ast::{CallExpression, NewExpression};

const MESSAGE: &str = "Make sure granting all privileges is safe here.";

/// `S6302`: IAM policies should not grant all privileges (`Action: "*"`).
///
/// Flags statements whose action list contains the `*` literal while the
/// effect is missing or `ALLOW`.
pub(crate) fn check_s6302_all_privileges_new(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    for (style, view) in policy_statements_new(file, new_expression) {
        check_statement(file, style, view, sink);
    }
}

pub(crate) fn check_s6302_all_privileges_call(
    file: &CdkFile,
    call: &CallExpression<'_>,
    sink: &mut IssueSink,
) {
    for (style, view) in policy_statements_call(file, call) {
        check_statement(file, style, view, sink);
    }
}

fn check_statement(
    file: &CdkFile,
    style: PolicyStyle,
    view: PropsView<'_, '_>,
    sink: &mut IssueSink,
) {
    let (_, actions_key, ..) = style.keys();
    let Some(actions) = property_value(view, actions_key) else {
        return;
    };
    if !file.value_strings(&actions).contains(&"*") {
        return;
    }
    if matches!(
        policy_effect(file, style, &view),
        EffectState::Missing | EffectState::Allow
    ) {
        let span = wildcard_span(&actions, "*").unwrap_or_else(|| actions.span());
        sink.emit_span(RuleScope::Both, "S6302", MESSAGE, span);
    }
}
