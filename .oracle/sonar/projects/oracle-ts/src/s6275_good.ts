import { aws_ec2 } from 'aws-cdk-lib';

// Volume encrypted at rest.
new aws_ec2.Volume(this, 'EncryptedVolume', {
  encrypted: true,
});
