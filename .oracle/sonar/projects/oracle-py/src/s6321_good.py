from aws_cdk import aws_ec2 as ec2

ingress = ec2.CfnSecurityGroupIngress(
    scope,
    "ssh",
    ip_protocol="tcp",
    cidr_ip="192.0.2.0/24",
    from_port=22,
    to_port=22,
    group_id="sg-0123",
)

