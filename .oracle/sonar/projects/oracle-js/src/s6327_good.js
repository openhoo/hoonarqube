import { aws_sns } from 'aws-cdk-lib';

// Topic encrypted with a KMS key.
new aws_sns.Topic(this, 'Topic', {
  masterKey: 'alias/example-key',
});
