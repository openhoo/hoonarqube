from aws_cdk import aws_s3 as s3

bucket = s3.Bucket(
    scope,
    "assets",
    block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
)

