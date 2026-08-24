// Rule module s6304_all_resources.
use super::shared::{
    CdkFile, EffectState, PolicyStyle, PropsView, policy_effect, policy_statements_call,
    policy_statements_new, property_value, wildcard_span,
};
use crate::support::IssueSink;
use crate::support::RuleScope;
use oxc_ast::ast::{CallExpression, NewExpression};

const MESSAGE: &str = "Make sure granting access to all resources is safe here.";
const KMS_PREFIX: &str = "kms:";

/// `S6304`: IAM policies should not grant access to all resources
/// (`Resource: "*"`).
///
/// Flags statements whose resource list contains the `*` literal while the
/// effect is missing or `ALLOW`. KMS key policies (every action
/// `kms:`-prefixed) are exempt, mirroring the upstream exception.
pub(crate) fn check_s6304_all_resources_new(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    for (style, view) in policy_statements_new(file, new_expression) {
        check_statement(file, style, view, sink);
    }
}

pub(crate) fn check_s6304_all_resources_call(
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
    let (_, actions_key, resources_key, _) = style.keys();
    let Some(resources) = property_value(view, resources_key) else {
        return;
    };
    if !file.value_strings(&resources).contains(&"*") {
        return;
    }
    // Exception: KMS key policies must target `*` but scope via the key.
    let actions = property_value(view, actions_key);
    let action_strings: Vec<&str> = match &actions {
        Some(actions) => file.value_strings(actions),
        None => Vec::new(),
    };
    if action_strings
        .iter()
        .all(|action| action.starts_with(KMS_PREFIX))
    {
        return;
    }
    if matches!(
        policy_effect(file, style, &view),
        EffectState::Missing | EffectState::Allow
    ) {
        let span = wildcard_span(&resources, "*").unwrap_or_else(|| resources.span());
        sink.emit_span(RuleScope::Both, "S6304", MESSAGE, span);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6304_flags_wildcard_resource_policies() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6304"))
                .count()
        };

        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             new iam.PolicyStatement({\n\
             \x20 effect: iam.Effect.ALLOW,\n\
             \x20 actions: ['s3:GetObject'],\n\
             \x20 resources: ['*'],\n\
             });\n"
            ),
            1
        );

        // KMS key policies are exempt from the wildcard-resource flag.
        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             new iam.PolicyStatement({\n\
             \x20 effect: iam.Effect.ALLOW,\n\
             \x20 actions: ['kms:Decrypt'],\n\
             \x20 resources: ['*'],\n\
             });\n"
            ),
            0
        );

        // Clean: scoped resource.
        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             new iam.PolicyStatement({\n\
             \x20 actions: ['s3:GetObject'],\n\
             \x20 resources: ['arn:aws:s3:::bucket/*'],\n\
             });\n"
            ),
            0
        );
    }
}
