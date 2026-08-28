import { aws_iam } from 'aws-cdk-lib';

// Statement applies to every resource in the account.
new aws_iam.PolicyStatement({
  effect: aws_iam.Effect.ALLOW,
  actions: ['s3:GetObject'],
  resources: ['*'],
});
