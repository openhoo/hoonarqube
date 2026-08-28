import { aws_sqs } from 'aws-cdk-lib';

// Queue encrypted with a managed KMS key.
new aws_sqs.Queue(this, 'Queue', {
  encryption: aws_sqs.QueueEncryption.KMS_MANAGED,
});

// L1 queue with an explicit KMS master key.
new aws_sqs.CfnQueue(this, 'CfnQueue', {
  kmsMasterKeyId: 'alias/example-key',
});
