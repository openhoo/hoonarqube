// Rule module s6270_iam_public_access.
use super::shared::{
    CdkFile, EffectState, PolicyStyle, PropsView, ValueView, policy_effect, policy_statements_call,
    policy_statements_new, property_value, value_elements, value_object,
};
use crate::support::IssueSink;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_span::{GetSpan, Span};

const MESSAGE: &str = "Make sure granting public access is safe here.";

/// `S6270`: AWS resource-based policies should not grant public access.
///
/// Flags statements whose `principals` (CDK style) or `Principal` (JSON
/// style) is `*`, a `StarPrincipal`/`AnyPrincipal`, or an `ArnPrincipal('*')`
/// while the effect is missing or `ALLOW`. `ArnPrincipal` arguments are only
/// inspectable on live expressions; digested values are conservatively
/// skipped.
pub(crate) fn check_s6270_iam_public_access_new(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    for (style, view) in policy_statements_new(file, new_expression) {
        check_statement(file, style, view, sink);
    }
}

pub(crate) fn check_s6270_iam_public_access_call(
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
    let (_, _, _, principals_key) = style.keys();
    let Some(principals) = property_value(view, principals_key) else {
        return;
    };
    let Some(span) = sensitive_principal(file, style, &principals) else {
        return;
    };
    if matches!(
        policy_effect(file, style, &view),
        EffectState::Missing | EffectState::Allow
    ) {
        sink.emit_span(RuleScope::Both, "S6270", MESSAGE, span);
    }
}

fn sensitive_principal(
    file: &CdkFile,
    style: PolicyStyle,
    value: &ValueView<'_, '_>,
) -> Option<Span> {
    match style {
        PolicyStyle::Cdk => cdk_principal_sensitive(file, value),
        PolicyStyle::Json => json_principal_sensitive(file, value),
    }
}

fn cdk_principal_sensitive(file: &CdkFile, value: &ValueView<'_, '_>) -> Option<Span> {
    let mut elements = value_elements(*value);
    if elements.is_empty() {
        elements.push(*value);
    }
    elements
        .iter()
        .find_map(|element| match file.value_new_fqn(element)?.as_str() {
            "aws_cdk_lib.aws_iam.StarPrincipal" | "aws_cdk_lib.aws_iam.AnyPrincipal" => {
                Some(element.span())
            }
            "aws_cdk_lib.aws_iam.ArnPrincipal" => arn_principal_wildcard_span(file, element),
            _ => None,
        })
}

fn arn_principal_wildcard_span(file: &CdkFile, element: &ValueView<'_, '_>) -> Option<Span> {
    let ValueView::Live(expression) = element else {
        return None;
    };
    let Expression::NewExpression(new) = unparenthesized(expression) else {
        return None;
    };
    let argument = new.arguments.first()?.as_expression()?;
    (file.value_str(&ValueView::Live(argument)) == Some("*")).then(|| argument.span())
}

fn json_principal_sensitive(file: &CdkFile, value: &ValueView<'_, '_>) -> Option<Span> {
    if file.value_str(value) == Some("*") {
        return Some(value.span());
    }
    let object = value_object(*value)?;
    let aws = property_value(object, "AWS")?;
    (file.value_strings(&aws).contains(&"*")).then(|| aws.span())
}
