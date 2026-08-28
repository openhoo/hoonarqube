use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::int_literal_value;
use crate::support::issue_at;
use crate::support::keyword_range;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6321_admin_ports_open_world(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let open_world = keyword_value(&call.arguments, "cidr_ip")
            .and_then(string_literal_text)
            .as_deref()
            == Some("0.0.0.0/0")
            || keyword_value(&call.arguments, "cidr_ipv6")
                .and_then(string_literal_text)
                .as_deref()
                == Some("::/0");
        let admin_port = ["from_port", "to_port"].iter().any(|name| {
            keyword_value(&call.arguments, name)
                .and_then(int_literal_value)
                .is_some_and(|port| ADMIN_PORTS.contains(&port))
        });
        if called_name(&call.func) == Some("CfnSecurityGroupIngress") && open_world && admin_port {
            let range = keyword_range(&call.arguments, "cidr_ip")
                .or_else(|| keyword_range(&call.arguments, "cidr_ipv6"))
                .unwrap_or_else(|| call.range());
            issues.push(issue_at(
                "python:S6321",
                "Change this IP range to a subset of trusted IP addresses.",
                range,
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S6321 — administration services restricted by IP ----------------------

const ADMIN_PORTS: [i64; 2] = [22, 3389];
