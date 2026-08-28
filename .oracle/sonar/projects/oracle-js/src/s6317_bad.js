import { aws_iam } from 'aws-cdk-lib';

// Privilege-escalation action scoped to every role in the account.
new aws_iam.PolicyStatement({
  effect: aws_iam.Effect.ALLOW,
  actions: ['sts:AssumeRole'],
  resources: ['*:*:*:*:role/*'],
  principals: [new aws_iam.ServicePrincipal('ec2.amazonaws.com')],
});
