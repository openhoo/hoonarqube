import { aws_sagemaker } from 'aws-cdk-lib';

// Notebook instance without a KMS encryption key.
new aws_sagemaker.CfnNotebookInstance(this, 'Notebook');
