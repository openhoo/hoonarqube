from aws_cdk import aws_efs as efs

filesystem = efs.FileSystem(scope, "data", encrypted=False)

