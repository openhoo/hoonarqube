from aws_cdk.aws_iam import PolicyStatement

policy = PolicyStatement(
    actions=["lambda:UpdateFunctionCode"],
    resources=["arn:aws:lambda:eu-central-1:123456789012:function:worker"],
)

