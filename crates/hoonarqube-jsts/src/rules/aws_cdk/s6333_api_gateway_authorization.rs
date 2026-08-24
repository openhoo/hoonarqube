// Rule module s6333_api_gateway_authorization.
use super::shared::{CdkFile, ValueView, property_value};
use crate::support::IssueSink;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_span::{GetSpan, Span};

const PUBLIC_API: &str = "Make sure that creating public APIs is safe here.";
const OMITTED: &str =
    "Omitting \"authorizationType\" disables authentication. Make sure it is safe here.";
const REST_API: &str = "aws_cdk_lib.aws_apigateway.RestApi";
const AUTHORIZATION_TYPE_NONE: &str = "aws_cdk_lib.aws_apigateway.AuthorizationType.NONE";

/// `S6333`: API Gateway methods should require authorization.
///
/// Flags `CfnMethod`/`CfnRoute` constructs with `authorizationType: 'NONE'`
/// or without the key, and `restApi.root.addMethod(...)` calls whose method
/// options (or the API's `defaultMethodOptions`) authorize `NONE`. The
/// `addResource` default-propagation chain is not covered (documented honest
/// subset).
pub(crate) fn check_s6333_api_gateway_authorization_new(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    let is_method = file.is_cdk(
        &new_expression.callee,
        "aws_cdk_lib.aws_apigateway.CfnMethod",
    );
    let is_route = file.is_cdk(
        &new_expression.callee,
        "aws_cdk_lib.aws_apigatewayv2.CfnRoute",
    );
    if !is_method && !is_route {
        return;
    }
    let props = file.props_arg(&new_expression.arguments, 2);
    if props.provably_absent() {
        sink.emit_span(
            RuleScope::Both,
            "S6333",
            OMITTED,
            new_expression.callee.span(),
        );
        return;
    }
    let Some(view) = props.view() else {
        return;
    };
    match property_value(view, "authorizationType") {
        Some(value) => {
            if is_none_authorization(file, &value) {
                sink.emit_span(RuleScope::Both, "S6333", PUBLIC_API, value.span());
            }
        }
        None => sink.emit_span(
            RuleScope::Both,
            "S6333",
            OMITTED,
            new_expression.callee.span(),
        ),
    }
}

pub(crate) fn check_s6333_api_gateway_authorization_call(
    file: &CdkFile,
    call: &CallExpression<'_>,
    sink: &mut IssueSink,
) {
    let Expression::StaticMemberExpression(add_method) = unparenthesized(&call.callee) else {
        return;
    };
    if add_method.property.name.as_str() != "addMethod" {
        return;
    }
    let Expression::StaticMemberExpression(root) = unparenthesized(&add_method.object) else {
        return;
    };
    if root.property.name.as_str() != "root" {
        return;
    }
    let api = &root.object;
    let is_rest_api = match unparenthesized(api) {
        Expression::NewExpression(new) => file.is_cdk(&new.callee, REST_API),
        Expression::Identifier(identifier) => {
            file.bound_new_is_cdk(identifier.name.as_str(), REST_API)
        }
        _ => false,
    };
    if !is_rest_api {
        return;
    }
    let default_authorization = file.rest_api_default_authorization(&ValueView::Live(api));
    let options = file.props_arg(&call.arguments, 1);
    if let Some(value) = options
        .view()
        .and_then(|view| property_value(view, "authorizationType"))
    {
        if is_none_authorization(file, &value) {
            sink.emit_span(RuleScope::Both, "S6333", PUBLIC_API, value.span());
        }
    } else {
        let span = method_options_span(call);
        match default_authorization.as_deref() {
            Some("NONE") => sink.emit_span(RuleScope::Both, "S6333", PUBLIC_API, span),
            None => sink.emit_span(RuleScope::Both, "S6333", OMITTED, span),
            Some(_) => {}
        }
    }
}

fn is_none_authorization(file: &CdkFile, value: &ValueView<'_, '_>) -> bool {
    file.value_str(value) == Some("NONE")
        || file.value_fqn(value).as_deref() == Some(AUTHORIZATION_TYPE_NONE)
}

fn method_options_span(call: &CallExpression<'_>) -> Span {
    call.arguments
        .get(1)
        .and_then(oxc_ast::ast::Argument::as_expression)
        .map_or(call.span(), oxc_span::GetSpan::span)
}
