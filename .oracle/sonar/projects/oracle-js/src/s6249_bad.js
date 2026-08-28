import { aws_s3 } from 'aws-cdk-lib';

// Omitting 'enforceSSL' authorizes plain HTTP requests.
new aws_s3.Bucket(this, 'InsecureBucket', {
  versioned: true,
});
