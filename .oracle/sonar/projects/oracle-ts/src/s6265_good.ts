import { aws_s3 } from 'aws-cdk-lib';

// Private bucket without public grants.
new aws_s3.Bucket(this, 'PrivateBucket', {
  accessControl: aws_s3.BucketAccessControl.PRIVATE,
  publicReadAccess: false,
  enforceSSL: true,
  versioned: true,
});
