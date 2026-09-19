use crate::engine::file_context::FileContext;
use crate::support::AwsLambdaFacts;
use crate::support::innermost_function;
use crate::support::is_boto3_client_method_call;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Number;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtWhile;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

// --- python:S7621 — AWS waiters instead of custom polling loops ------------

const MESSAGE: &str = "Use AWS waiters instead of custom polling loops.";

/// `botocore.client.BaseClient` describe/head/get methods that have a
/// dedicated waiter (Sonar's `NON_WAITERS_BOTO3_METHODS`, names only).
const POLLING_METHODS: &[&str] = &[
    // EC2
    "describe_instances",
    "describe_instance_status",
    "describe_volumes",
    "describe_snapshots",
    "describe_images",
    "describe_vpcs",
    "describe_subnets",
    "describe_nat_gateways",
    "describe_key_pairs",
    "get_password_data",
    // S3
    "head_bucket",
    "head_object",
    // RDS
    "describe_db_instances",
    "describe_db_clusters",
    "describe_db_snapshots",
    // DynamoDB
    "describe_table",
    // ECS
    "describe_services",
    "describe_tasks",
    // EKS
    "describe_cluster",
    "describe_nodegroup",
    // CloudFormation
    "describe_stacks",
    "describe_change_set",
    // Lambda
    "get_function_configuration",
    "get_function",
];

pub(crate) fn check_s7621_aws_waiters(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let lambda = AwsLambdaFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !POLLING_METHODS
            .iter()
            .any(|method| is_boto3_client_method_call(&lambda.facts, call, method))
        {
            continue;
        }
        let Some(while_stmt) = enclosing_while(file_ctx, call.range()) else {
            continue;
        };
        if !is_truthy(&lambda, &while_stmt.test) {
            continue;
        }
        let Some(function) = innermost_function(file_ctx, call.range()) else {
            continue;
        };
        if lambda.is_lambda_handler(function) {
            issues.push(issue_at(
                "python:S7621",
                MESSAGE,
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// Innermost `while` containing `at` (`firstAncestorOfKind(WHILE_STMT)` —
/// function boundaries do not stop the search).
fn enclosing_while<'a>(file_ctx: &'a FileContext<'a>, at: TextRange) -> Option<&'a StmtWhile> {
    file_ctx
        .stmts
        .iter()
        .filter_map(|stmt| match *stmt {
            Stmt::While(while_stmt) => Some(while_stmt),
            _ => None,
        })
        .filter(|while_stmt| while_stmt.range().contains_range(at))
        .min_by_key(|while_stmt| while_stmt.range().len().to_u32())
}

/// `Expressions.isTruthy`: `True`, non-empty literals, non-zero numbers, and
/// names whose single assignment is truthy.
fn is_truthy(lambda: &AwsLambdaFacts<'_>, expr: &Expr) -> bool {
    if let Expr::Name(name) = expr {
        if name.id.as_str() == "True" {
            return true;
        }
        return lambda
            .facts
            .single_assigned_value(name.id.as_str(), expr.range())
            .is_some_and(is_truthy_internal);
    }
    is_truthy_internal(expr)
}

fn is_truthy_internal(expr: &Expr) -> bool {
    match expr {
        Expr::BooleanLiteral(literal) => literal.value,
        Expr::StringLiteral(_) => string_literal_text(expr).is_some_and(|text| !text.is_empty()),
        Expr::NumberLiteral(number) => !is_zero_number(&number.value),
        Expr::List(list) => !list.elts.is_empty(),
        Expr::Tuple(tuple) => !tuple.elts.is_empty(),
        Expr::Set(set) => !set.elts.is_empty(),
        Expr::Dict(dict) => !dict.items.is_empty(),
        _ => false,
    }
}

fn is_zero_number(number: &Number) -> bool {
    match number {
        Number::Int(value) => value.as_i64() == Some(0),
        Number::Float(value) => *value == 0.0,
        Number::Complex { real, imag } => *real == 0.0 && *imag == 0.0,
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7621";

    #[test]
    fn s7621_flags_polling_loop_in_handler() {
        let source = "import boto3\nimport time\n\nec2_client = boto3.client('ec2', region_name='us-east-1')\n\ndef lambda_handler(event, context):\n    while True:\n        response = ec2_client.describe_instance_status(\n            InstanceIds=[event['id']],\n            IncludeAllInstances=True\n        )\n        instance_status = response['Statuses'][0]['InstanceStatus']['Status']\n        if instance_status == 'ok':\n            break\n        time.sleep(10)\n";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Use AWS waiters instead of custom polling loops."
        );
    }

    #[test]
    fn s7621_accepts_waiter_usage() {
        let source = "import boto3\n\nec2_client = boto3.client('ec2', region_name='us-east-1')\n\ndef lambda_handler(event, context):\n    ec2_client.get_waiter('instance_status_ok').wait(\n        InstanceIds=[event['id']],\n        IncludeAllInstances=True\n    )\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7621_ignores_bounded_loops_and_non_handlers() {
        let bounded = "import boto3\n\nec2 = boto3.client('ec2')\n\ndef lambda_handler(event, context):\n    attempts = 0\n    while attempts < 3:\n        attempts += 1\n        status = ec2.describe_instances()\n";
        assert!(findings(&scan(bounded), KEY).is_empty());
        let outside = "import boto3\n\nec2 = boto3.client('ec2')\n\nwhile True:\n    status = ec2.describe_instances()\n    break\n";
        assert!(findings(&scan(outside), KEY).is_empty());
    }
}
