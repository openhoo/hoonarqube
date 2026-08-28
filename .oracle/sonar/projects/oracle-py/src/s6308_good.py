from aws_cdk.aws_opensearchservice import Domain, EncryptionAtRestOptions

domain = Domain(
    scope,
    "logs",
    encryption_at_rest=EncryptionAtRestOptions(enabled=True),
)

