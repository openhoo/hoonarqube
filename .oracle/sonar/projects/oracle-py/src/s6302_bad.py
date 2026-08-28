from aws_cdk.aws_iam import PolicyStatement

policy = PolicyStatement(
    actions=["*"],
    resources=["arn:aws:iam:::user/*"],
)

