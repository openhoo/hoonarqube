import { aws_sagemaker } from 'aws-cdk-lib';

// Notebook instance encrypted with a customer-managed KMS key.
new aws_sagemaker.CfnNotebookInstance(this, 'Notebook', {
  kmsKeyId: 'arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
});
