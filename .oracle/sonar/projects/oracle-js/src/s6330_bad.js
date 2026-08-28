import { aws_sqs } from 'aws-cdk-lib';

// Queue encryption switched off entirely.
new aws_sqs.Queue(this, 'Queue', {
  encryption: aws_sqs.QueueEncryption.UNENCRYPTED,
});

// L1 queue without a KMS master key.
new aws_sqs.CfnQueue(this, 'CfnQueue');
