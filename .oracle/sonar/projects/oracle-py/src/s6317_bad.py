from aws_cdk.aws_iam import PolicyStatement

policy = PolicyStatement(
    actions=["lambda:UpdateFunctionCode"],
    resources=["*"],
)

