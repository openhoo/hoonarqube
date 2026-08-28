from aws_cdk import aws_sqs as sqs

queue = sqs.CfnQueue(scope, "jobs")

