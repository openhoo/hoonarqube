from aws_cdk import aws_apigatewayv2 as apigateway

route = apigateway.CfnRoute(
    scope,
    "route",
    api_id="api",
    route_key="GET /items",
    authorization_type="AWS_IAM",
)

