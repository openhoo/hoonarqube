import { aws_s3 } from 'aws-cdk-lib';

// HTTPS-only bucket access is enforced.
new aws_s3.Bucket(this, 'SecureBucket', {
  versioned: true,
  enforceSSL: true,
});
