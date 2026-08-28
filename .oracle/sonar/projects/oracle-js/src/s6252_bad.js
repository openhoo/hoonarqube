import { aws_s3 } from 'aws-cdk-lib';

// Versioning explicitly disabled on the bucket.
new aws_s3.Bucket(this, 'UnversionedBucket', {
  enforceSSL: true,
  versioned: false,
});
