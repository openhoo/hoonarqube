from aws_cdk import aws_sagemaker as sagemaker

notebook = sagemaker.CfnNotebookInstance(
    scope,
    "notebook",
    instance_type="ml.t2.medium",
    role_arn="arn:aws:iam::123456789012:role/notebook",
    kms_key_id="alias/notebook",
)

