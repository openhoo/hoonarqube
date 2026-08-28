from aws_cdk.aws_iam import PolicyStatement

policy = PolicyStatement(
    actions=["iam:GetAccountSummary"],
    resources=["arn:aws:iam:::user/*"],
)

