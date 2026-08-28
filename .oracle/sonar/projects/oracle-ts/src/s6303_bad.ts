import { aws_rds } from 'aws-cdk-lib';

// Storage encryption disabled for the database instance.
new aws_rds.DatabaseInstance(this, 'Database', {
  storageEncrypted: false,
});
