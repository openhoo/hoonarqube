import { aws_s3 } from 'aws-cdk-lib';

// All public access block settings enabled.
new aws_s3.Bucket(this, 'FullyBlockedBucket', {
  blockPublicAccess: new aws_s3.BlockPublicAccess({
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
  }),
  enforceSSL: true,
  versioned: true,
});
