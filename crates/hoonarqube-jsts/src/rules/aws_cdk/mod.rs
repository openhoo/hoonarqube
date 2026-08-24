// Family 'aws_cdk': AWS CDK construct-prop call-shape checks (library-config
// Tier-B inspection). Semantics mirror the upstream SonarJS AWS rules; every
// check is a conservative, file-local syntactic subset documented on the rule.
pub(crate) mod s6249_s3_insecure_http;
pub(crate) mod s6252_s3_versioning;
pub(crate) mod s6265_s3_public_access;
pub(crate) mod s6270_iam_public_access;
pub(crate) mod s6275_ebs_encryption;
pub(crate) mod s6281_s3_public_access_block;
pub(crate) mod s6302_all_privileges;
pub(crate) mod s6303_rds_encryption;
pub(crate) mod s6304_all_resources;
pub(crate) mod s6308_opensearch_encryption;
pub(crate) mod s6317_wildcard_action_scope;
pub(crate) mod s6319_sagemaker_encryption;
pub(crate) mod s6321_admin_ports_open_world;
pub(crate) mod s6327_sns_encryption;
pub(crate) mod s6329_public_network_access;
pub(crate) mod s6330_sqs_encryption;
pub(crate) mod s6332_efs_encryption;
pub(crate) mod s6333_api_gateway_authorization;
pub(crate) mod shared;

use crate::Issue;
use crate::context::AnalysisContext;
use crate::support::IssueSink;
use oxc_ast::ast::{CallExpression, NewExpression};
use oxc_ast_visit::Visit;
use shared::CdkFile;

/// Runs every aws-cdk rule against the context.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    let file = CdkFile::build(ctx.program);
    let mut pass = shared::RulePass {
        file: &file,
        sink: &mut sink,
    };
    pass.visit_program(ctx.program);
    sink.issues
}

/// Dispatches one construct instantiation to every matching check.
fn dispatch_new(file: &CdkFile, expression: &NewExpression<'_>, sink: &mut IssueSink) {
    s6249_s3_insecure_http::check_s6249_s3_insecure_http(file, expression, sink);
    s6252_s3_versioning::check_s6252_s3_versioning(file, expression, sink);
    s6265_s3_public_access::check_s6265_s3_public_access_new(file, expression, sink);
    s6281_s3_public_access_block::check_s6281_s3_public_access_block(file, expression, sink);
    s6270_iam_public_access::check_s6270_iam_public_access_new(file, expression, sink);
    s6302_all_privileges::check_s6302_all_privileges_new(file, expression, sink);
    s6303_rds_encryption::check_s6303_rds_encryption(file, expression, sink);
    s6308_opensearch_encryption::check_s6308_opensearch_encryption(file, expression, sink);
    s6319_sagemaker_encryption::check_s6319_sagemaker_encryption(file, expression, sink);
    s6327_sns_encryption::check_s6327_sns_encryption(file, expression, sink);
    s6330_sqs_encryption::check_s6330_sqs_encryption(file, expression, sink);
    s6332_efs_encryption::check_s6332_efs_encryption(file, expression, sink);
    s6329_public_network_access::check_s6329_public_network_access(file, expression, sink);
    s6321_admin_ports_open_world::check_s6321_admin_ports_open_world_new(file, expression, sink);
    s6333_api_gateway_authorization::check_s6333_api_gateway_authorization_new(
        file, expression, sink,
    );
    s6304_all_resources::check_s6304_all_resources_new(file, expression, sink);
    s6317_wildcard_action_scope::check_s6317_wildcard_action_scope_new(file, expression, sink);
    s6275_ebs_encryption::check_s6275_ebs_encryption(file, expression, sink);
}

/// Dispatches one call expression to every matching check.
fn dispatch_call(file: &CdkFile, expression: &CallExpression<'_>, sink: &mut IssueSink) {
    s6265_s3_public_access::check_s6265_s3_public_access_call(file, expression, sink);
    s6270_iam_public_access::check_s6270_iam_public_access_call(file, expression, sink);
    s6321_admin_ports_open_world::check_s6321_admin_ports_open_world_call(file, expression, sink);
    s6333_api_gateway_authorization::check_s6333_api_gateway_authorization_call(
        file, expression, sink,
    );
    s6302_all_privileges::check_s6302_all_privileges_call(file, expression, sink);
    s6304_all_resources::check_s6304_all_resources_call(file, expression, sink);
    s6317_wildcard_action_scope::check_s6317_wildcard_action_scope_call(file, expression, sink);
}
