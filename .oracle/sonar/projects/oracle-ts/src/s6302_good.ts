import { aws_iam } from 'aws-cdk-lib';

// Only the required S3 actions are granted.
new aws_iam.PolicyStatement({
  effect: aws_iam.Effect.ALLOW,
  actions: ['s3:GetObject', 's3:ListBucket'],
  resources: ['arn:aws:s3:::example-bucket/*'],
});
