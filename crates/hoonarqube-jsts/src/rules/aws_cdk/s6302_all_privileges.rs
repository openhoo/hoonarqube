// Rule module s6302_all_privileges.
use super::shared::{
    CdkFile, EffectState, PolicyStyle, PropsView, policy_effect, policy_statements_call,
    policy_statements_new, property_value, wildcard_span,
};
use crate::support::IssueSink;
use crate::support::RuleScope;
use oxc_ast::ast::{CallExpression, NewExpression};

const MESSAGE: &str = "Make sure granting all privileges is safe here.";

/// `S6302`: IAM policies should not grant all privileges (`Action: "*"`).
///
/// Flags statements whose action list contains the `*` literal while the
/// effect is missing or `ALLOW`.
pub(crate) fn check_s6302_all_privileges_new(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    for (style, view) in policy_statements_new(file, new_expression) {
        check_statement(file, style, view, sink);
    }
}

pub(crate) fn check_s6302_all_privileges_call(
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
    let (_, actions_key, ..) = style.keys();
    let Some(actions) = property_value(view, actions_key) else {
        return;
    };
    if !file.value_strings(&actions).contains(&"*") {
        return;
    }
    if matches!(
        policy_effect(file, style, &view),
        EffectState::Missing | EffectState::Allow
    ) {
        let span = wildcard_span(&actions, "*").unwrap_or_else(|| actions.span());
        sink.emit_span(RuleScope::Both, "S6302", MESSAGE, span);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6302_flags_wildcard_action_policies() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6302"))
                .count()
        };

        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             new iam.PolicyStatement({\n\
             \x20 effect: iam.Effect.ALLOW,\n\
             \x20 actions: ['s3:*', '*'],\n\
             \x20 resources: ['arn:aws:s3:::bucket/*'],\n\
             });\n"
            ),
            1
        );

        // JSON style via PolicyDocument.fromJson.
        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             iam.PolicyDocument.fromJson({\n\
             \x20 Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],\n\
             });\n"
            ),
            1
        );

        // Clean: concrete actions.
        assert_eq!(
            count(
                "import * as iam from 'aws-cdk-lib/aws-iam';\n\
             new iam.PolicyStatement({\n\
             \x20 effect: iam.Effect.ALLOW,\n\
             \x20 actions: ['s3:GetObject'],\n\
             \x20 resources: ['*'],\n\
             });\n"
            ),
            0
        );
    }
}
