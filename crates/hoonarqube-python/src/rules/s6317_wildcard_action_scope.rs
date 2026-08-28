use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use crate::support::wildcard_literal;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6317_wildcard_action_scope(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("PolicyStatement")
            && keyword_value(&call.arguments, "actions").is_some_and(has_escalation_action)
            && let Some(wildcard) =
                keyword_value(&call.arguments, "resources").and_then(wildcard_literal)
        {
            issues.push(issue_at(
                "python:S6317",
                "This policy is vulnerable to the \"\" privilege escalation vector. Remove permissions or restrict the set of resources they apply to.",
                wildcard.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S6317 — wildcard-scoped actions in policies ---------------------------

fn has_escalation_action(value: &Expr) -> bool {
    match value {
        Expr::List(list) => list.elts.iter().any(has_escalation_action),
        Expr::Tuple(tuple) => tuple.elts.iter().any(has_escalation_action),
        Expr::StringLiteral(_) => string_literal_text(value)
            .is_some_and(|action| ESCALATION_ACTIONS.contains(&action.as_str())),
        _ => false,
    }
}

const ESCALATION_ACTIONS: [&str; 9] = [
    "lambda:UpdateFunctionCode",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
];
