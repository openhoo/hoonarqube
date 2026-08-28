import { aws_sns } from 'aws-cdk-lib';

// Topic without a KMS master key.
new aws_sns.Topic(this, 'Topic');
