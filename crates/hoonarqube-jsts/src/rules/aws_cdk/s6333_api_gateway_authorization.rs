// Rule module s6333_api_gateway_authorization.
use super::shared::{CdkFile, PropsArg, ValueView, property_value};
use crate::support::IssueSink;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_span::{GetSpan, Span};

const PUBLIC_API: &str = "Make sure that creating public APIs is safe here.";
const OMITTED: &str =
    "Omitting \"authorizationType\" disables authentication. Make sure it is safe here.";
const REST_API: &str = "aws_cdk_lib.aws_apigateway.RestApi";
const METHOD_OPTIONS_POSITION: usize = 2;
const AUTHORIZATION_TYPE_NONE: &str = "aws_cdk_lib.aws_apigateway.AuthorizationType.NONE";

/// `S6333`: API Gateway methods should require authorization.
///
/// Flags `CfnMethod`/`CfnRoute` constructs with `authorizationType: 'NONE'`
/// or without the key, and `RestApi.root.addMethod(...)` calls whose method
/// options (or the API's `defaultMethodOptions`) authorize `NONE`. Only
/// receivers with real RestApi-root provenance are considered.
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
    if !is_rest_api(file, api) {
        return;
    }
    let default_authorization = file.rest_api_default_authorization(&ValueView::Live(api));
    let options = file.props_arg(&call.arguments, METHOD_OPTIONS_POSITION);
    if matches!(&options, PropsArg::Opaque) {
        return;
    }
    if let Some(value) = options
        .view()
        .and_then(|view| property_value(view, "authorizationType"))
    {
        if is_none_authorization(file, &value) {
            sink.emit_span(RuleScope::Both, "S6333", PUBLIC_API, value.span());
        }
        return;
    }
    let span = method_options_span(call);
    match default_authorization.as_deref() {
        Some("NONE" | AUTHORIZATION_TYPE_NONE) => {
            sink.emit_span(RuleScope::Both, "S6333", PUBLIC_API, span);
        }
        None => sink.emit_span(RuleScope::Both, "S6333", OMITTED, span),
        Some(_) => {}
    }
}

fn is_rest_api<'p>(file: &CdkFile<'p>, expression: &Expression<'p>) -> bool {
    match unparenthesized(expression) {
        Expression::NewExpression(new) => file.is_cdk(&new.callee, REST_API),
        Expression::Identifier(identifier) => {
            file.bound_new_is_cdk(identifier.name.as_str(), REST_API)
        }
        _ => false,
    }
}

fn is_none_authorization(file: &CdkFile, value: &ValueView<'_, '_>) -> bool {
    file.value_str(value) == Some("NONE")
        || file.value_fqn(value).as_deref() == Some(AUTHORIZATION_TYPE_NONE)
}

fn method_options_span(call: &CallExpression<'_>) -> Span {
    call.arguments
        .get(METHOD_OPTIONS_POSITION)
        .and_then(oxc_ast::ast::Argument::as_expression)
        .map_or(call.span(), oxc_span::GetSpan::span)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6333_flags_public_api_gateway_methods() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6333"))
                .count()
        };

        // CfnMethod with NONE authorization.
        assert_eq!(
            count(
                "import * as apigateway from 'aws-cdk-lib/aws-apigateway';\n\
             new apigateway.CfnMethod(this, 'M', { authorizationType: 'NONE' });\n"
            ),
            1
        );

        // CfnMethod without authorizationType.
        assert_eq!(
            count(
                "import * as apigateway from 'aws-cdk-lib/aws-apigateway';\n\
             new apigateway.CfnMethod(this, 'M', { httpMethod: 'GET' });\n"
            ),
            1
        );

        // root.addMethod without authorization and without API default.
        assert_eq!(
            count(
                "import * as apigateway from 'aws-cdk-lib/aws-apigateway';\n\
             const api = new apigateway.RestApi(this, 'Api');\n\
             api.root.addMethod('GET');\n"
            ),
            1
        );

        // root.addMethod inheriting a NONE default; MethodOptions is third.
        assert_eq!(
            count(
                "import * as apigateway from 'aws-cdk-lib/aws-apigateway';\n\
             const api = new apigateway.RestApi(this, 'Api', {\n\
             \x20 defaultMethodOptions: { authorizationType: 'NONE' },\n\
             });\n\
             api.root.addMethod('GET', new apigateway.HttpIntegration('https://example.org'), {});\n"
            ),
            1
        );

        // Clean: the real integration is second and IAM MethodOptions third.
        assert_eq!(
            count(
                "import * as apigateway from 'aws-cdk-lib/aws-apigateway';\n\
             const api = new apigateway.RestApi(this, 'Api');\n\
             api.root.addMethod('GET', new apigateway.HttpIntegration('https://example.org'), {\n\
             \x20 authorizationType: apigateway.AuthorizationType.IAM,\n\
             });\n"
            ),
            0
        );

        // A same-shaped unrelated object is not a real API Gateway resource.
        assert_eq!(
            count(
                "import * as apigateway from 'aws-cdk-lib/aws-apigateway';\n\
             const fake = { root: { addMethod() {} } };\n\
             fake.root.addMethod('GET', new apigateway.HttpIntegration('https://example.org'), {\n\
             \x20 authorizationType: apigateway.AuthorizationType.NONE,\n\
             });\n"
            ),
            0
        );
    }

    #[test]
    fn s6333_supports_typescript_method_options_near_shape() {
        let count = |source: &str| -> usize {
            ts(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6333"))
                .count()
        };

        assert_eq!(
            count(
                "import { aws_apigateway } from 'aws-cdk-lib';\n\
             const api = new aws_apigateway.RestApi(this, 'Api');\n\
             api.root.addMethod('GET', new aws_apigateway.HttpIntegration('https://example.org'), {\n\
             \x20 authorizationType: aws_apigateway.AuthorizationType.IAM,\n\
             });\n"
            ),
            0
        );
        assert_eq!(
            count(
                "import { aws_apigateway } from 'aws-cdk-lib';\n\
             const api = new aws_apigateway.RestApi(this, 'Api');\n\
             api.root.addMethod('GET', new aws_apigateway.HttpIntegration('https://example.org'), {\n\
             \x20 authorizationType: aws_apigateway.AuthorizationType.NONE,\n\
             });\n"
            ),
            1
        );
    }
}
