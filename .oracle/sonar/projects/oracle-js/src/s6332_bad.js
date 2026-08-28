import { aws_efs } from 'aws-cdk-lib';

// L2 file system explicitly unencrypted.
new aws_efs.FileSystem(this, 'FileSystem', {
  encrypted: false,
});

// L1 file system without the encrypted flag.
new aws_efs.CfnFileSystem(this, 'CfnFileSystem');
