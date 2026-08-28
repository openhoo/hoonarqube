import { aws_s3 } from 'aws-cdk-lib';

// Bucket policies can still grant public access with this block mode.
new aws_s3.Bucket(this, 'PartialBlockBucket', {
  blockPublicAccess: new aws_s3.BlockPublicAccess({
    blockPublicAcls: true,
    blockPublicPolicy: false,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
  }),
  enforceSSL: true,
  versioned: true,
});
