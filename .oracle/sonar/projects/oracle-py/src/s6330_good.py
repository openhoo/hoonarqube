from aws_cdk import aws_sqs as sqs

queue = sqs.CfnQueue(scope, "jobs", kms_master_key_id="alias/jobs")

