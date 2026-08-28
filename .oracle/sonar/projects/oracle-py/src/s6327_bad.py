from aws_cdk import aws_sns as sns

topic = sns.CfnTopic(scope, "alerts")

