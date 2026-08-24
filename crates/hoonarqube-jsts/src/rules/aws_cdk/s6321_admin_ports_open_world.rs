// Rule module s6321_admin_ports_open_world.
use super::shared::{
    CdkFile, PropsArg, PropsView, ValueView, property_value, value_elements, value_object,
};
use crate::support::IssueSink;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{Argument, CallExpression, Expression, NewExpression};
use oxc_span::GetSpan;

const ALLOW_FROM: &str = "Change this IP range to a subset of trusted IP addresses.";
const ALLOW_FROM_ANY_IPV4: &str =
    "Change this method for \"allowFrom\" and set \"other\" to a subset of trusted IP addresses.";

const BAD_PORTS: [f64; 2] = [22.0, 3389.0];
const ANY_IPV4: &str = "0.0.0.0/0";
const ANY_IPV6: &str = "::/0";

const SECURITY_GROUP: &str = "aws_cdk_lib.aws_ec2.CfnSecurityGroup";
const SECURITY_GROUP_INGRESS: &str = "aws_cdk_lib.aws_ec2.CfnSecurityGroupIngress";

/// `S6321`: admin ports (SSH 22, RDP 3389) must not be reachable from the
/// open world.
///
/// Flags `connections.allowFromAnyIpv4(...)`/`allowDefaultPortFromAnyIpv4(...)`
/// with a bad port, `allowFrom(...)`/`addIngressRule(...)` combining a bad
/// peer (`Peer.anyIpv4/anyIpv6`, `Peer.ipv4('0.0.0.0/0')`,
/// `Peer.ipv6('::/0')`) with a bad port, and `CfnSecurityGroup(Ingress)`
/// ingress objects opening those ports to `0.0.0.0/0`/`::/0`. Port and peer
/// arguments are only recognized through their `aws-cdk-lib` `ec2` FQNs;
/// constructor `defaultPort` propagation is not covered (documented honest
/// subset).
pub(crate) fn check_s6321_admin_ports_open_world_call(
    file: &CdkFile,
    call: &CallExpression<'_>,
    sink: &mut IssueSink,
) {
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return;
    };
    match member.property.name.as_str() {
        "allowFromAnyIpv4" | "allowDefaultPortFromAnyIpv4" => {
            let port = call.arguments.first().and_then(argument_view);
            if port.is_some_and(|port| bad_port(file, &port)) {
                sink.emit_span(
                    RuleScope::Both,
                    "S6321",
                    ALLOW_FROM_ANY_IPV4,
                    call.callee.span(),
                );
            }
        }
        "allowFrom" | "addIngressRule" => {
            let peer = call.arguments.first().and_then(argument_view);
            let port = call.arguments.get(1).and_then(argument_view);
            if peer.is_some_and(|peer| bad_peer(file, &peer))
                && port.is_some_and(|port| bad_port(file, &port))
            {
                let span = call
                    .arguments
                    .first()
                    .map_or_else(|| call.span(), oxc_span::GetSpan::span);
                sink.emit_span(RuleScope::Both, "S6321", ALLOW_FROM, span);
            }
        }
        _ => {}
    }
}

pub(crate) fn check_s6321_admin_ports_open_world_new(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    if file.is_cdk(&new_expression.callee, SECURITY_GROUP_INGRESS) {
        if let Some(view) = file.props_arg(&new_expression.arguments, 2).view() {
            check_ingress(file, view, sink);
        }
        return;
    }
    if !file.is_cdk(&new_expression.callee, SECURITY_GROUP) {
        return;
    }
    let Some(view) = file.props_arg(&new_expression.arguments, 2).view() else {
        return;
    };
    let Some(ingress) = property_value(view, "securityGroupIngress") else {
        return;
    };
    for element in value_elements(ingress) {
        if let Some(object) = value_object(element) {
            check_ingress(file, object, sink);
        }
    }
}

fn check_ingress(file: &CdkFile, view: PropsView<'_, '_>, sink: &mut IssueSink) {
    for (ip_key, bad_ip) in [("cidrIp", ANY_IPV4), ("cidrIpv6", ANY_IPV6)] {
        let Some(ip) = property_value(view, ip_key) else {
            continue;
        };
        if file.value_str(&ip) != Some(bad_ip) {
            continue;
        }
        let protocol = property_value(view, "ipProtocol")
            .and_then(|value| file.value_str(&value).map(str::to_owned));
        let from_port = number_prop(file, view, "fromPort");
        let to_port = number_prop(file, view, "toPort");
        if protocol.as_deref() == Some("-1")
            || (matches!(protocol.as_deref(), Some("tcp" | "6" | "TCP"))
                && disallowed_port_range(from_port, to_port))
        {
            sink.emit_span(RuleScope::Both, "S6321", ALLOW_FROM, ip.span());
        }
    }
}

fn number_prop(file: &CdkFile, view: PropsView<'_, '_>, key: &str) -> Option<f64> {
    property_value(view, key).and_then(|value| file.value_number(&value))
}

fn bad_port(file: &CdkFile, view: &ValueView<'_, '_>) -> bool {
    // Only live `ec2.Port...` shapes are provable; digested facts are skipped.
    let Some((callee, arguments)) = live_call(view) else {
        return false;
    };
    let Some(fqn) = file.fqn(callee) else {
        return false;
    };
    match fqn.as_str() {
        "aws_cdk_lib.aws_ec2.Port.allTcp" | "aws_cdk_lib.aws_ec2.Port.allTraffic" => true,
        "aws_cdk_lib.aws_ec2.Port.tcp" => arguments
            .first()
            .and_then(argument_view)
            .and_then(|argument| file.value_number(&argument))
            .is_some_and(|port| BAD_PORTS.contains(&port)),
        "aws_cdk_lib.aws_ec2.Port.tcpRange" => {
            let start = arguments.first().and_then(argument_view);
            let end = arguments.get(1).and_then(argument_view);
            disallowed_port_range(
                start.and_then(|argument| file.value_number(&argument)),
                end.and_then(|argument| file.value_number(&argument)),
            )
        }
        "aws_cdk_lib.aws_ec2.Port" => match file.props_arg(arguments, 0) {
            PropsArg::Live(props) => {
                let view = PropsView::Live(props);
                let protocol = property_value(view, "protocol")
                    .is_some_and(|value| bad_protocol(file, &value));
                let from = number_prop(file, view, "fromPort");
                let to = number_prop(file, view, "toPort");
                protocol && disallowed_port_range(from, to)
            }
            _ => false,
        },
        _ => false,
    }
}

fn bad_peer(file: &CdkFile, view: &ValueView<'_, '_>) -> bool {
    let Some((callee, _)) = live_call(view) else {
        return false;
    };
    match file.fqn(callee).as_deref() {
        Some("aws_cdk_lib.aws_ec2.Peer.anyIpv4" | "aws_cdk_lib.aws_ec2.Peer.anyIpv6") => true,
        Some("aws_cdk_lib.aws_ec2.Peer.ipv4") => {
            first_argument_str(file, view).as_deref() == Some(ANY_IPV4)
        }
        Some("aws_cdk_lib.aws_ec2.Peer.ipv6") => {
            first_argument_str(file, view).as_deref() == Some(ANY_IPV6)
        }
        _ => false,
    }
}

fn bad_protocol(file: &CdkFile, value: &ValueView<'_, '_>) -> bool {
    matches!(file.value_str(value), Some("tcp" | "6" | "TCP"))
        || matches!(
            file.value_fqn(value).as_deref(),
            Some("aws_cdk_lib.aws_ec2.Protocol.ALL" | "aws_cdk_lib.aws_ec2.Protocol.TCP")
        )
}

fn disallowed_port_range(start: Option<f64>, end: Option<f64>) -> bool {
    match (start, end) {
        (Some(start), Some(end)) => BAD_PORTS.iter().any(|port| *port >= start && *port <= end),
        (Some(start), None) => BAD_PORTS.contains(&start),
        _ => false,
    }
}

fn first_argument_str(file: &CdkFile, view: &ValueView<'_, '_>) -> Option<String> {
    let (_, arguments) = live_call(view)?;
    let argument = argument_view(arguments.first()?)?;
    file.value_str(&argument).map(str::to_owned)
}

/// Callee and arguments of a live constructor/factory call (`new X(...)` or
/// `X.y(...)`), the shapes `ec2.Peer`/`ec2.Port` factories use.
fn live_call<'a, 'p>(
    view: &'a ValueView<'_, 'p>,
) -> Option<(&'a Expression<'p>, &'a [Argument<'p>])> {
    let ValueView::Live(expression) = view else {
        return None;
    };
    match unparenthesized(expression) {
        Expression::NewExpression(new) => Some((&new.callee, &new.arguments)),
        Expression::CallExpression(call) => Some((&call.callee, &call.arguments)),
        _ => None,
    }
}

fn argument_view<'a, 'p>(argument: &'a Argument<'p>) -> Option<ValueView<'a, 'p>> {
    argument.as_expression().map(ValueView::Live)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6321_flags_admin_ports_open_to_world() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6321"))
                .count()
        };

        // SSH opened to any IPv4 via allowFromAnyIpv4.
        assert_eq!(
            count(
                "import * as ec2 from 'aws-cdk-lib/aws-ec2';\n\
             sg.connections.allowFromAnyIpv4(ec2.Port.tcp(22));\n"
            ),
            1
        );

        // allowFrom with open peer and admin port.
        assert_eq!(
            count(
                "import * as ec2 from 'aws-cdk-lib/aws-ec2';\n\
             sg.connections.allowFrom(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.tcp(3389));\n"
            ),
            1
        );

        // CfnSecurityGroupIngress opening RDP to the world.
        assert_eq!(
            count(
                "import * as ec2 from 'aws-cdk-lib/aws-ec2';\n\
             new ec2.CfnSecurityGroupIngress(this, 'Ingress', {\n\
             \x20 cidrIp: '0.0.0.0/0',\n\
             \x20 ipProtocol: 'tcp',\n\
             \x20 fromPort: 22,\n\
             \x20 toPort: 22,\n\
             });\n"
            ),
            1
        );

        // Clean: restricted peer and port.
        assert_eq!(
            count(
                "import * as ec2 from 'aws-cdk-lib/aws-ec2';\n\
             sg.connections.allowFrom(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(22));\n"
            ),
            0
        );

        // Clean: open world but a non-admin port.
        assert_eq!(
            count(
                "import * as ec2 from 'aws-cdk-lib/aws-ec2';\n\
             sg.connections.allowFrom(ec2.Peer.anyIpv4(), ec2.Port.tcp(8443));\n"
            ),
            0
        );
    }
}
