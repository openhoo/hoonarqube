import { aws_rds } from 'aws-cdk-lib';

// Storage encryption enabled for the database instance.
new aws_rds.DatabaseInstance(this, 'Database', {
  storageEncrypted: true,
});
