import { aws_efs } from 'aws-cdk-lib';

// L2 file systems default to encryption at rest.
new aws_efs.FileSystem(this, 'FileSystem');

// L1 file system with encryption enabled explicitly.
new aws_efs.CfnFileSystem(this, 'CfnFileSystem', {
  encrypted: true,
});
