use super::s6252_s3_versioning::S3Bindings;
use crate::engine::file_context::FileContext;
use crate::support::{
    WebFrameworkFacts, aws_fqn, has_unknown_keyword_unpack, is_false_literal, issue_at,
    keyword_value, literal_unpacked_keyword, resolved_value, string_literal_text,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6249 — S3 buckets should enforce HTTPS-only access --------------

const NO_POLICY_MESSAGE: &str =
    "No bucket policy enforces HTTPS-only access to this bucket. Make sure it is safe here.";
const HTTP_ALLOWED_MESSAGE: &str = "Make sure authorizing HTTP requests is safe here.";

/// `enforce_ssl` argument of a bucket constructor: the keyword, or a
/// literal-dict `**{"enforce_ssl": ...}` unpack.
fn enforce_ssl_value(call: &ExprCall) -> Option<&Expr> {
    keyword_value(&call.arguments, "enforce_ssl")
        .or_else(|| literal_unpacked_keyword(&call.arguments, "enforce_ssl"))
}

/// The single `name = <bucket call>` binding enclosing `call`, matching the
/// reference's `firstAncestorOfKind(ASSIGNMENT_STMT)` + single-LHS-name
/// requirement (tuple, chained, and subscript targets track nothing).
fn bucket_variable_name<'a>(file_ctx: &FileContext<'a>, call: &ExprCall) -> Option<&'a str> {
    file_ctx.stmts.iter().find_map(|stmt| {
        if !stmt.range().contains_range(call.range()) {
            return None;
        }
        match stmt {
            Stmt::Assign(assign) if assign.targets.len() == 1 => {
                if let Expr::Name(name) = &assign.targets[0] {
                    Some(name.id.as_str())
                } else {
                    None
                }
            }
            Stmt::AnnAssign(assign) if assign.value.is_some() => {
                if let Expr::Name(name) = assign.target.as_ref() {
                    Some(name.id.as_str())
                } else {
                    None
                }
            }
            _ => None,
        }
    })
}

/// First `<name>.add_to_resource_policy(...)` call in the file (the
/// reference inspects the first usage only).
fn first_policy_call<'a>(file_ctx: &FileContext<'a>, bucket_name: &str) -> Option<&'a ExprCall> {
    file_ctx.calls.iter().find_map(|call| {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            return None;
        };
        if attribute.attr.as_str() != "add_to_resource_policy" {
            return None;
        }
        matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == bucket_name)
            .then_some(*call)
    })
}

/// First argument of `add_to_resource_policy` when it is a
/// `aws_cdk.aws_iam.PolicyStatement` constructor call.
fn policy_statement_call<'a>(
    facts: &WebFrameworkFacts<'_>,
    call: &'a ExprCall,
) -> Option<&'a ExprCall> {
    let first = call.arguments.args.first().or_else(|| {
        call.arguments
            .keywords
            .first()
            .map(|keyword| &keyword.value)
    })?;
    let Expr::Call(statement) = first else {
        return None;
    };
    (aws_fqn(facts, &statement.func).as_deref() == Some("aws_cdk.aws_iam.PolicyStatement"))
        .then_some(statement)
}

/// Whether the `name` keyword of `call` is a list literal containing the
/// string `expected` (name-resolved one level, like the reference's
/// argument flow).
fn list_arg_contains(
    facts: &WebFrameworkFacts<'_>,
    call: &ExprCall,
    name: &str,
    expected: &str,
) -> bool {
    let Some(value) = keyword_value(&call.arguments, name) else {
        return false;
    };
    let Expr::List(list) = resolved_value(facts, value) else {
        return false;
    };
    list.elts
        .iter()
        .any(|element| string_literal_text(element).as_deref() == Some(expected))
}

/// A compliant HTTPS-deny policy needs `Effect.DENY`, wildcard resources,
/// `s3:*` actions, wildcard principals, and a `SecureTransport:False`
/// condition.
fn is_https_deny_policy(facts: &WebFrameworkFacts<'_>, statement: &ExprCall) -> bool {
    let deny = keyword_value(&statement.arguments, "effect").is_some_and(|value| {
        aws_fqn(facts, resolved_value(facts, value)).as_deref()
            == Some("aws_cdk.aws_iam.Effect.DENY")
    });
    deny && list_arg_contains(facts, statement, "resources", "*")
        && list_arg_contains(facts, statement, "actions", "s3:*")
        && list_arg_contains(facts, statement, "principals", "*")
        && list_arg_contains(facts, statement, "conditions", "SecureTransport:False")
}

pub(crate) fn check_s6249_s3_https_only(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let bindings = S3Bindings::collect(file_ctx);
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !bindings.is_s3_bucket_constructor(&call.func, call.range().start())
            || has_unknown_keyword_unpack(&call.arguments)
        {
            continue;
        }
        if let Some(value) = enforce_ssl_value(call) {
            if is_false_literal(resolved_value(&facts, value)) {
                issues.push(issue_at(
                    "python:S6249",
                    HTTP_ALLOWED_MESSAGE,
                    call.func.range(),
                    index,
                    source,
                ));
            }
            continue;
        }
        let compliant = bucket_variable_name(file_ctx, call)
            .and_then(|name| first_policy_call(file_ctx, name))
            .and_then(|policy_call| policy_statement_call(&facts, policy_call))
            .is_some_and(|statement| is_https_deny_policy(&facts, statement));
        if compliant {
            continue;
        }
        // A non-compliant `PolicyStatement` is reported on the statement;
        // every other shape reports the bucket constructor.
        let flagged_statement = bucket_variable_name(file_ctx, call)
            .and_then(|name| first_policy_call(file_ctx, name))
            .and_then(|policy_call| policy_statement_call(&facts, policy_call));
        if let Some(statement) = flagged_statement {
            issues.push(issue_at(
                "python:S6249",
                HTTP_ALLOWED_MESSAGE,
                statement.func.range(),
                index,
                source,
            ));
        } else {
            issues.push(issue_at(
                "python:S6249",
                NO_POLICY_MESSAGE,
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, findings_of, scan};

    #[test]
    fn s6249_flags_buckets_without_enforce_ssl() {
        let flagged = concat!(
            "import aws_cdk.aws_iam as iam\nimport aws_cdk.aws_s3 as s3\n",
            "no_config = s3.Bucket(self, 'bucket')\n",
            "ssl_false = s3.Bucket(self, 'bucket', enforce_ssl=False)\n",
        );
        let found = findings_of(flagged, "python:S6249");
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0],
            "No bucket policy enforces HTTPS-only access to this bucket. Make sure it is safe here."
        );
        assert_eq!(
            found[1],
            "Make sure authorizing HTTP requests is safe here."
        );
    }

    #[test]
    fn s6249_accepts_enforce_ssl_and_compliant_deny_policy() {
        let compliant = concat!(
            "import aws_cdk.aws_iam as iam\nimport aws_cdk.aws_s3 as s3\n",
            "ssl_true = s3.Bucket(self, 'bucket', enforce_ssl=True)\n",
            "ssl_unknown = s3.Bucket(self, 'bucket', enforce_ssl=foo())\n",
            "correct = s3.Bucket(self, 'bucket')\n",
            "correct.add_to_resource_policy(\n",
            "    iam.PolicyStatement(\n",
            "        effect=iam.Effect.DENY,\n",
            "        resources=['*'],\n",
            "        actions=['s3:*'],\n",
            "        principals=['*'],\n",
            "        conditions=['SecureTransport:False'],\n",
            "    )\n",
            ")\n",
        );
        assert!(findings(&scan(compliant), "python:S6249").is_empty());
    }

    #[test]
    fn s6249_flags_incomplete_policy_statements() {
        let flagged = concat!(
            "import aws_cdk.aws_iam as iam\nimport aws_cdk.aws_s3 as s3\n",
            "bucket = s3.Bucket(self, 'bucket')\n",
            "bucket.add_to_resource_policy(\n",
            "    iam.PolicyStatement(\n",
            "        effect=iam.Effect.DENY,\n",
            "        resources=['*'],\n",
            "        actions=['s3:SomeAction'],\n",
            "        principals=['*'],\n",
            "        conditions=['SecureTransport:False'],\n",
            "    )\n",
            ")\n",
        );
        let found = findings_of(flagged, "python:S6249");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0],
            "Make sure authorizing HTTP requests is safe here."
        );
    }

    #[test]
    fn s6249_flags_buckets_without_policy_calls() {
        let flagged = concat!(
            "import aws_cdk.aws_iam as iam\nimport aws_cdk.aws_s3 as s3\n",
            "empty_policy = s3.Bucket(self, 'bucket')\n",
            "empty_policy.add_to_resource_policy()\n",
            "no_policy = s3.Bucket(self, 'bucket')\n",
            "no_policy.foo(iam.PolicyStatement(effect=iam.Effect.DENY, resources=['*'], actions=['s3:*'], principals=['*'], conditions=['SecureTransport:False']))\n",
            "not_statement = s3.Bucket(self, 'bucket')\n",
            "not_statement.add_to_resource_policy(iam.Foo())\n",
        );
        let found = findings_of(flagged, "python:S6249");
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|message| {
            message
                == "No bucket policy enforces HTTPS-only access to this bucket. Make sure it is safe here."
        }));
    }

    #[test]
    fn s6249_ignores_non_bucket_constructs() {
        let compliant = concat!(
            "import aws_cdk.aws_iam as iam\nimport aws_cdk.aws_s3 as s3\n",
            "a = s3.something(self, 'bucket')\n",
            "a.add_to_resource_policy(\n",
            "    iam.PolicyStatement(effect=iam.Effect.DENY, resources=['x'], actions=['s3:x'], principals=['y'], conditions=['z'])\n",
            ")\n",
        );
        assert!(findings(&scan(compliant), "python:S6249").is_empty());
    }
}
