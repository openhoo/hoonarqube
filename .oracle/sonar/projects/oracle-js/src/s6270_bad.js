import { aws_iam } from 'aws-cdk-lib';

// StarPrincipal allows every AWS principal while the effect is ALLOW.
new aws_iam.PolicyStatement({
  effect: aws_iam.Effect.ALLOW,
  actions: ['s3:GetObject'],
  resources: ['arn:aws:s3:::example-bucket/*'],
  principals: [new aws_iam.StarPrincipal()],
});
