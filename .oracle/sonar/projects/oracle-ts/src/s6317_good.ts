import { aws_iam } from 'aws-cdk-lib';

// Privilege-escalation action restricted to one concrete role.
new aws_iam.PolicyStatement({
  effect: aws_iam.Effect.ALLOW,
  actions: ['sts:AssumeRole'],
  resources: ['arn:aws:iam::123456789012:role/deploy'],
  principals: [new aws_iam.ServicePrincipal('ec2.amazonaws.com')],
});
