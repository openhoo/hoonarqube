import { aws_iam } from 'aws-cdk-lib';

// KMS key policies must target '*' but are scoped by the key itself.
new aws_iam.PolicyStatement({
  effect: aws_iam.Effect.ALLOW,
  actions: ['kms:Decrypt'],
  resources: ['*'],
});
