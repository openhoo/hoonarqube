use crate::engine::file_context::FileContext;
use crate::support::AwsLambdaFacts;
use crate::support::NameResolution;
use crate::support::innermost_function;
use crate::support::is_boto3_client_method_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtTry;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

// --- python:S7619 — ClientError must be caught around boto3 calls ----------

const MESSAGE: &str = "Wrap this AWS client call in a try-except block to handle \"botocore.exceptions.ClientError\".";

/// `botocore.client.BaseClient` methods that raise `ClientError`
/// (Sonar's `EXCEPTION_THROWING_METHODS`, method names only).
const EXCEPTION_THROWING_METHODS: &[&str] = &[
    // S3
    "get_object",
    "put_object",
    "create_bucket",
    "delete_object",
    "delete_bucket",
    "list_objects_v2",
    "copy_object",
    "head_object",
    "get_bucket_location",
    "put_bucket_policy",
    "get_bucket_policy",
    "delete_bucket_policy",
    // EC2
    "describe_instances",
    "run_instances",
    "terminate_instances",
    "start_instances",
    "stop_instances",
    "create_security_group",
    "delete_security_group",
    "describe_security_groups",
    "create_vpc",
    "delete_vpc",
    "describe_vpcs",
    // Lambda
    "create_function",
    "update_function_code",
    "update_function_configuration",
    "delete_function",
    "invoke",
    "get_function",
    "list_functions",
    // DynamoDB
    "get_item",
    "put_item",
    "delete_item",
    "update_item",
    "query",
    "scan",
    "create_table",
    "delete_table",
    "describe_table",
    // RDS
    "create_db_instance",
    "delete_db_instance",
    "describe_db_instances",
    "modify_db_instance",
    "reboot_db_instance",
    // IAM
    "create_user",
    "delete_user",
    "get_user",
    "create_role",
    "delete_role",
    "get_role",
    "attach_user_policy",
    "detach_user_policy",
    // CloudFormation
    "create_stack",
    "delete_stack",
    "describe_stacks",
    "update_stack",
    // SNS
    "create_topic",
    "delete_topic",
    "publish",
    "subscribe",
    "unsubscribe",
    // SQS
    "create_queue",
    "delete_queue",
    "send_message",
    "receive_message",
    "delete_message",
];

pub(crate) fn check_s7619_client_error_handling(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let lambda = AwsLambdaFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(function) = innermost_function(file_ctx, call.range()) else {
            continue;
        };
        // `isOnlyLambdaHandler`: signature handlers only, no call-graph walk.
        if !lambda.is_only_lambda_handler(function) {
            continue;
        }
        if !EXCEPTION_THROWING_METHODS
            .iter()
            .any(|method| is_boto3_client_method_call(&lambda.facts, call, method))
        {
            continue;
        }
        if !is_wrapped_in_client_error_handler(&lambda, file_ctx, call.range()) {
            issues.push(issue_at(
                "python:S7619",
                MESSAGE,
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// Whether `at` sits inside a `try` (in its own scope or an enclosing one)
/// whose handlers catch `ClientError` or a parent of it.
fn is_wrapped_in_client_error_handler(
    lambda: &AwsLambdaFacts<'_>,
    file_ctx: &FileContext,
    at: TextRange,
) -> bool {
    let mut current = at;
    loop {
        let Some(try_stmt) = enclosing_try_in_scope(lambda, file_ctx, current) else {
            return false;
        };
        if try_catches_client_error(lambda, try_stmt) {
            return true;
        }
        current = try_stmt.range();
    }
}

/// Innermost `try` strictly containing `at` inside `at`'s own scope —
/// `TreeUtils.firstAncestorOfKind(TRY_STMT, FUNCDEF, LAMBDA)` stops at
/// function/lambda boundaries, so a `try` in an outer scope does not count.
fn enclosing_try_in_scope<'a>(
    lambda: &AwsLambdaFacts<'a>,
    file_ctx: &'a FileContext<'a>,
    at: TextRange,
) -> Option<&'a StmtTry> {
    let scope = lambda.facts.enclosing_scope(at);
    file_ctx
        .stmts
        .iter()
        .filter_map(|stmt| match *stmt {
            Stmt::Try(try_stmt) => Some(try_stmt),
            _ => None,
        })
        .filter(|try_stmt| {
            try_stmt.range() != at
                && try_stmt.range().contains_range(at)
                && scope.is_none_or(|scope| scope.contains_range(try_stmt.range()))
        })
        .min_by_key(|try_stmt| try_stmt.range().len().to_u32())
}

fn try_catches_client_error(lambda: &AwsLambdaFacts<'_>, try_stmt: &StmtTry) -> bool {
    try_stmt.handlers.iter().any(|handler| {
        let ExceptHandler::ExceptHandler(handler) = handler;
        match handler.type_.as_deref() {
            // A bare `except:` catches everything.
            None => true,
            Some(exception) => is_client_error_or_parent(lambda, exception),
        }
    })
}

fn is_client_error_or_parent(lambda: &AwsLambdaFacts<'_>, exception: &Expr) -> bool {
    match exception {
        Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .any(|element| is_client_error_or_parent(lambda, element)),
        Expr::Name(name) => {
            match lambda
                .facts
                .resolve_name(name.id.as_str(), exception.range())
            {
                // `Exception`/`BaseException` are builtins: they resolve only
                // when unbound in the file's own scopes.
                NameResolution::Unbound => {
                    matches!(name.id.as_str(), "Exception" | "BaseException")
                }
                NameResolution::Import(fqn) => {
                    fqn == "botocore.exceptions.ClientError"
                        || fqn == "builtins.Exception"
                        || fqn == "builtins.BaseException"
                }
                _ => false,
            }
        }
        _ => lambda
            .facts
            .expr_fqn(exception)
            .is_some_and(|fqn| fqn == "botocore.exceptions.ClientError"),
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7619";

    #[test]
    fn s7619_flags_unguarded_boto3_call_in_handler() {
        let source = "import boto3\n\ns3 = boto3.client(\"s3\")\n\ndef lambda_handler(event, context):\n    return s3.get_object(Bucket=\"my_bucket\", Key=\"somefile.txt\")\n";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Wrap this AWS client call in a try-except block to handle \"botocore.exceptions.ClientError\"."
        );
    }

    #[test]
    fn s7619_accepts_client_error_handler() {
        let source = "import boto3\nfrom botocore.exceptions import ClientError\n\ns3 = boto3.client(\"s3\")\n\ndef lambda_handler(event, context):\n    try:\n        response = s3.get_object(Bucket=\"my_bucket\", Key=\"somefile.txt\")\n    except ClientError as e:\n        error_code = e.response['Error']['Code']\n        if error_code == 'NoSuchKey':\n            return {\"error\": \"File not found\"}\n        raise\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7619_accepts_broad_and_bare_handlers() {
        for handler in ["Exception", "BaseException", ""] {
            let clause = if handler.is_empty() {
                "except:".to_string()
            } else {
                format!("except {handler}:")
            };
            let source = format!(
                "import boto3\n\ns3 = boto3.client(\"s3\")\n\ndef lambda_handler(event, context):\n    try:\n        return s3.get_object(Bucket=\"b\", Key=\"k\")\n    {clause}\n        return None\n"
            );
            assert!(findings(&scan(&source), KEY).is_empty(), "{clause}");
        }
    }

    #[test]
    fn s7619_flags_try_that_misses_client_error() {
        let source = "import boto3\n\ns3 = boto3.client(\"s3\")\n\ndef lambda_handler(event, context):\n    try:\n        return s3.get_object(Bucket=\"b\", Key=\"k\")\n    except KeyError:\n        return None\n";
        assert_eq!(findings(&scan(source), KEY).len(), 1);
    }

    #[test]
    fn s7619_accepts_outer_try_catching_client_error() {
        let source = "import boto3\nfrom botocore.exceptions import ClientError\n\ns3 = boto3.client(\"s3\")\n\ndef lambda_handler(event, context):\n    try:\n        try:\n            return s3.get_object(Bucket=\"b\", Key=\"k\")\n        except KeyError:\n            pass\n    except ClientError:\n        return None\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7619_ignores_calls_outside_handlers() {
        let source = "import boto3\n\ns3 = boto3.client(\"s3\")\n\ndef fetch(name):\n    return s3.get_object(Bucket=\"b\", Key=name)\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7619_ignores_non_client_receivers() {
        let source = "def lambda_handler(event, context):\n    return event.get_object(Bucket=\"b\", Key=\"k\")\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }
}
