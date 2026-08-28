from aws_cdk.aws_iam import PolicyStatement

policy = PolicyStatement(
    actions=["iam:CreatePolicyVersion"],
    resources=["arn:aws:iam::123456789012:policy/team/*"],
)

