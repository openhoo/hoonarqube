// Rule module s6317_wildcard_action_scope.
use super::shared::{
    CdkFile, EffectState, PolicyStyle, PropsView, policy_effect, policy_statements_call,
    policy_statements_new, property_value, wildcard_span,
};
use crate::support::IssueSink;
use crate::support::RuleScope;
use oxc_ast::ast::{CallExpression, NewExpression};

/// Actions known to enable privilege escalation when combined with
/// resource-scoped wildcards (upstream `SENSITIVE_ACTIONS`).
const SENSITIVE_ACTIONS: [&str; 27] = [
    "cloudformation:CreateStack",
    "datapipeline:CreatePipeline",
    "datapipeline:PutPipelineDefinition",
    "ec2:RunInstances",
    "glue:CreateDevEndpoint",
    "glue:UpdateDevEndpoint",
    "iam:AddUserToGroup",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:CreatePolicyVersion",
    "iam:PassRole",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:UpdateLoginProfile",
    "iam:UpdateRole",
    "lambda:AddPermission",
    "lambda:CreateEventSourceMapping",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "sts:AssumeRole",
];

/// `S6317`: privilege-escalation actions must not target wildcard
/// role/user/group resources (`*` or `*:*:*:*:(role|user|group)/*`).
pub(crate) fn check_s6317_wildcard_action_scope_new(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    for (style, view) in policy_statements_new(file, new_expression) {
        check_statement(file, style, view, sink);
    }
}

pub(crate) fn check_s6317_wildcard_action_scope_call(
    file: &CdkFile,
    call: &CallExpression<'_>,
    sink: &mut IssueSink,
) {
    for (style, view) in policy_statements_call(file, call) {
        check_statement(file, style, view, sink);
    }
}

fn check_statement(
    file: &CdkFile,
    style: PolicyStyle,
    view: PropsView<'_, '_>,
    sink: &mut IssueSink,
) {
    let (_, actions_key, resources_key, principals_key) = style.keys();
    // Exception: statements without an explicit principal are out of scope.
    if property_value(view, principals_key).is_none() {
        return;
    }
    let Some(actions) = property_value(view, actions_key) else {
        return;
    };
    let Some(action) = file
        .value_strings(&actions)
        .into_iter()
        .find(|action| SENSITIVE_ACTIONS.contains(action))
    else {
        return;
    };
    let Some(resources) = property_value(view, resources_key) else {
        return;
    };
    let Some(resource) = file
        .value_strings(&resources)
        .into_iter()
        .find(|resource| sensitive_resource(resource))
    else {
        return;
    };
    let resource_span = wildcard_span(&resources, resource).unwrap_or_else(|| resources.span());
    if matches!(
        policy_effect(file, style, &view),
        EffectState::Missing | EffectState::Allow
    ) {
        sink.emit_span(
            RuleScope::Both,
            "S6317",
            &format!(
                "This policy is vulnerable to the \"{action}\" privilege escalation vector. \
                 Remove permissions or restrict the set of resources they apply to."
            ),
            resource_span,
        );
    }
}

/// `*` or an account-scoped wildcard over roles, users, or groups.
fn sensitive_resource(resource: &str) -> bool {
    if resource == "*" {
        return true;
    }
    let parts: Vec<&str> = resource.split(':').collect();
    parts.len() == 5
        && parts[0] == "*"
        && parts[1..4].iter().all(|part| !part.contains('/'))
        && matches!(parts[4], "role/*" | "user/*" | "group/*")
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6317_flags_privilege_escalation_wildcards() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6317"))
                .count()
        };

        // iam:PassRole on all roles.
        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             new iam.PolicyStatement({\n\
             \x20 effect: iam.Effect.ALLOW,\n\
             \x20 actions: ['iam:PassRole'],\n\
             \x20 resources: ['*'],\n\
             \x20 principals: [new iam.ServicePrincipal('ec2.amazonaws.com')],\n\
             });\n"
            ),
            1
        );

        // Account-scoped wildcard role resource.
        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             new iam.PolicyStatement({\n\
             \x20 actions: ['sts:AssumeRole'],\n\
             \x20 resources: ['*:*:*:*:role/*'],\n\
             \x20 principals: [new iam.ServicePrincipal('ec2.amazonaws.com')],\n\
             });\n"
            ),
            1
        );

        // Clean: concrete role resource.
        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             new iam.PolicyStatement({\n\
             \x20 actions: ['sts:AssumeRole'],\n\
             \x20 resources: ['arn:aws:iam::123456789012:role/deploy'],\n\
             \x20 principals: [new iam.ServicePrincipal('ec2.amazonaws.com')],\n\
             });\n"
            ),
            0
        );
    }
}
