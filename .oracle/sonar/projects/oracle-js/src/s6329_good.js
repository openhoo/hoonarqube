import { aws_dms } from 'aws-cdk-lib';

// Replication instance not exposed publicly.
new aws_dms.CfnReplicationInstance(this, 'Replication', {
  publiclyAccessible: false,
});
