import { aws_ec2 } from 'aws-cdk-lib';

// Admin port restricted to a trusted range.
sg.connections.allowFrom(aws_ec2.Peer.ipv4('10.0.0.0/8'), aws_ec2.Port.tcp(22));

// Open peer with a non-admin port stays out of scope.
sg.connections.allowFrom(aws_ec2.Peer.anyIpv4(), aws_ec2.Port.tcp(8443));
