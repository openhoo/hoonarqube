import { aws_dms, aws_ec2 } from 'aws-cdk-lib';

// EC2 instance placed directly on a public subnet.
new aws_ec2.Instance(this, 'Instance', {
  vpcSubnets: {
    subnetType: aws_ec2.SubnetType.PUBLIC,
  },
});

// DMS replication instance exposed publicly.
new aws_dms.CfnReplicationInstance(this, 'Replication', {
  publiclyAccessible: true,
});
