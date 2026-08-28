import { aws_iam } from 'aws-cdk-lib';

// Every privilege granted to the statement scope.
new aws_iam.PolicyStatement({
  effect: aws_iam.Effect.ALLOW,
  actions: ['*'],
  resources: ['arn:aws:s3:::example-bucket/*'],
});
