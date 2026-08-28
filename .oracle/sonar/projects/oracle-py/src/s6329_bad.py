from aws_cdk import aws_rds as rds

database = rds.CfnDBInstance(
    scope,
    "database",
    db_instance_class="db.t3.micro",
    engine="postgres",
    publicly_accessible=True,
)

