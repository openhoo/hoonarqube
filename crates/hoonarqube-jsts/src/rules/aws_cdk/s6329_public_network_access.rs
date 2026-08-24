// Rule module s6329_public_network_access.
use super::shared::{CdkFile, PropsView, ValueView, property_value, value_object};
use crate::support::IssueSink;
use crate::support::RuleScope;
use oxc_ast::ast::NewExpression;

const MESSAGE: &str = "Make sure allowing public network access is safe here.";

const PUBLIC_SUBNET: &str = "aws_cdk_lib.aws_ec2.SubnetType.PUBLIC";
const PRIVATE_SUBNETS: [&str; 3] = [
    "aws_cdk_lib.aws_ec2.SubnetType.PRIVATE_ISOLATED",
    "aws_cdk_lib.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS",
    "aws_cdk_lib.aws_ec2.SubnetType.PRIVATE_WITH_NAT",
];

/// `S6329`: resources should not be exposed to public networks.
///
/// Flags `ec2.Instance` on a public subnet, `rds.DatabaseInstance` on a
/// public subnet without a private override (`publiclyAccessible: true` or
/// omitted), and `rds.CfnDBInstance`/`dms.CfnReplicationInstance` with
/// `publiclyAccessible: true`. The `CfnInstance` `networkInterfaces` shape
/// is not covered (documented honest subset).
pub(crate) fn check_s6329_public_network_access(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    let Some(fqn) = file.fqn(&new_expression.callee) else {
        return;
    };
    let Some(view) = file.props_arg(&new_expression.arguments, 2).view() else {
        return;
    };
    match fqn.as_str() {
        "aws_cdk_lib.aws_ec2.Instance" => {
            if let Some(subnet_type) = subnet_type(view)
                && file.value_fqn(&subnet_type).as_deref() == Some(PUBLIC_SUBNET)
            {
                sink.emit_span(RuleScope::Both, "S6329", MESSAGE, subnet_type.span());
            }
        }
        "aws_cdk_lib.aws_rds.DatabaseInstance" => {
            check_database_instance(file, view, sink);
        }
        "aws_cdk_lib.aws_rds.CfnDBInstance" | "aws_cdk_lib.aws_dms.CfnReplicationInstance" => {
            if let Some(value) = property_value(view, "publiclyAccessible")
                && file.value_bool(&value) == Some(true)
            {
                sink.emit_span(RuleScope::Both, "S6329", MESSAGE, value.span());
            }
        }
        _ => {}
    }
}

fn check_database_instance(file: &CdkFile, view: PropsView<'_, '_>, sink: &mut IssueSink) {
    let Some(subnet_type) = subnet_type(view) else {
        return;
    };
    let subnet_fqn = file.value_fqn(&subnet_type);
    if subnet_fqn
        .as_deref()
        .is_some_and(|fqn| PRIVATE_SUBNETS.contains(&fqn))
    {
        return;
    }
    if subnet_fqn.as_deref() != Some(PUBLIC_SUBNET) {
        return;
    }
    match property_value(view, "publiclyAccessible") {
        Some(value) => {
            if file.value_bool(&value) == Some(true) {
                sink.emit_span(RuleScope::Both, "S6329", MESSAGE, value.span());
            }
        }
        None => sink.emit_span(RuleScope::Both, "S6329", MESSAGE, subnet_type.span()),
    }
}

/// `vpcSubnets.subnetType` of a construct's props, when provable.
fn subnet_type<'a, 'p>(view: PropsView<'a, 'p>) -> Option<ValueView<'a, 'p>> {
    let vpc_subnets = property_value(view, "vpcSubnets")?;
    value_object(vpc_subnets).and_then(|object| property_value(object, "subnetType"))
}
