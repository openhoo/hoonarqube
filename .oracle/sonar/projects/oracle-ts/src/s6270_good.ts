import { aws_iam } from 'aws-cdk-lib';

// Concrete principal with a scoped resource.
new aws_iam.PolicyStatement({
  effect: aws_iam.Effect.ALLOW,
  actions: ['s3:GetObject'],
  resources: ['arn:aws:s3:::example-bucket/*'],
  principals: [new aws_iam.ArnPrincipal('arn:aws:iam::123456789012:user/app')],
});
