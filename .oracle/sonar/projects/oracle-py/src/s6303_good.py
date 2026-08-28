from aws_cdk import aws_rds as rds

database = rds.CfnDBCluster(scope, "database", storage_encrypted=True)

