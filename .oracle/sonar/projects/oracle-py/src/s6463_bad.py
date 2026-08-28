from aws_cdk import aws_ec2 as ec2

security_group = ec2.SecurityGroup(scope, "app", vpc=vpc)

