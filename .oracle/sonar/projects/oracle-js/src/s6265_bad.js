import { aws_s3 } from 'aws-cdk-lib';

// Objects readable by anyone on the internet.
new aws_s3.Bucket(this, 'PublicBucket', {
  accessControl: aws_s3.BucketAccessControl.PUBLIC_READ,
  enforceSSL: true,
  versioned: true,
});
