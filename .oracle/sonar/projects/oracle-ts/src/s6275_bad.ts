import { aws_ec2 } from 'aws-cdk-lib';

// Volume encryption explicitly disabled.
new aws_ec2.Volume(this, 'PlainVolume', {
  encrypted: false,
});
