import { aws_ec2 } from 'aws-cdk-lib';

// SSH reachable from any IPv4 address.
sg.connections.allowFromAnyIpv4(aws_ec2.Port.tcp(22));

// RDP opened to the whole internet.
sg.connections.allowFrom(aws_ec2.Peer.anyIpv4(), aws_ec2.Port.tcp(3389));
