from aws_cdk.aws_iam import PolicyStatement

policy = PolicyStatement(
    actions=["iam:CreatePolicyVersion"],
    resources=["*"],
)

