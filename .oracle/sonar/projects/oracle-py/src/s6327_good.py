from aws_cdk import aws_sns as sns

topic = sns.CfnTopic(scope, "alerts", kms_master_key_id="alias/alerts")

