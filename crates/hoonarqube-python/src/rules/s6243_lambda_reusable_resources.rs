use crate::engine::file_context::FileContext;
use crate::support::{AwsLambdaFacts, aws_fqn, innermost_function, issue_at};
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6243 — reusable resources initialized inside Lambda handlers ----

const CLIENT_MESSAGE: &str = "Initialize this AWS client outside the Lambda handler function.";
const DATABASE_MESSAGE: &str =
    "Initialize this database connection outside the Lambda handler function.";
const ORM_MESSAGE: &str = "Initialize this ORM connection outside the Lambda handler function.";

/// Message for a reusable-resource constructor FQN, or `None` when the call
/// does not create a shareable client/connection.
fn resource_message(fqn: &str) -> Option<&'static str> {
    const CLIENT_FQNS: &[&str] = &["boto3.client", "boto3.resource", "boto3.session.Session"];
    const DATABASE_FQNS: &[&str] = &[
        "pymysql.connect",
        "mysql.connector.connect",
        "psycopg2.connect",
        "pymongo.MongoClient",
        "sqlite3.dbapi2.connect",
        "sqlite3.connect",
        "redis.Redis",
        "redis.StrictRedis",
    ];
    const ORM_FQNS: &[&str] = &[
        "sqlalchemy.orm.sessionmaker",
        "peewee.PostgresqlDatabase",
        "peewee.MySQLDatabase",
        "peewee.SqliteDatabase",
        "mongoengine.connect",
    ];
    if CLIENT_FQNS.contains(&fqn) {
        Some(CLIENT_MESSAGE)
    } else if DATABASE_FQNS.contains(&fqn) {
        Some(DATABASE_MESSAGE)
    } else if ORM_FQNS.contains(&fqn) {
        Some(ORM_MESSAGE)
    } else {
        None
    }
}

pub(crate) fn check_s6243_lambda_reusable_resources(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let lambda = AwsLambdaFacts::build(file_ctx);
    if !lambda.has_handler() {
        return Vec::new();
    }
    let facts = &lambda.facts;
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !innermost_function(file_ctx, call.range())
            .is_some_and(|function| lambda.is_lambda_handler(function))
        {
            continue;
        }
        if let Some(message) = aws_fqn(facts, &call.func).and_then(|fqn| resource_message(&fqn)) {
            issues.push(issue_at(
                "python:S6243",
                message,
                call.range(),
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
    fn s6243_flags_clients_connections_and_orms_inside_handlers() {
        let flagged = concat!(
            "import boto3\n",
            "import pymysql\n",
            "import redis\n",
            "from sqlalchemy.orm import sessionmaker\n",
            "def lambda_handler(event, context):\n",
            "    s3 = boto3.client('s3')\n",
            "    db = pymysql.connect(host='localhost')\n",
            "    cache = redis.Redis(host='localhost')\n",
            "    maker = sessionmaker()\n",
        );
        let messages = findings_of(flagged, "python:S6243");
        assert_eq!(
            messages,
            [
                "Initialize this AWS client outside the Lambda handler function.".to_string(),
                "Initialize this database connection outside the Lambda handler function."
                    .to_string(),
                "Initialize this database connection outside the Lambda handler function."
                    .to_string(),
                "Initialize this ORM connection outside the Lambda handler function.".to_string(),
            ]
        );
    }

    #[test]
    fn s6243_flags_handler_signature_variants_and_called_helpers() {
        let flagged = concat!(
            "import boto3\n",
            "def helper():\n",
            "    return boto3.resource('s3')\n",
            "def orderHandler(event, ctx):\n",
            "    return helper()\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6243").len(), 1);
    }

    #[test]
    fn s6243_ignores_module_level_and_non_handler_functions() {
        let compliant = concat!(
            "import boto3\n",
            "s3 = boto3.client('s3')\n",
            "def lambda_handler(event, context):\n",
            "    return s3.get_object(Bucket='b', Key='k')\n",
            "def not_a_handler():\n",
            "    boto3.client('s3')\n",
            "def helper():\n",
            "    boto3.client('s3')\n",
        );
        assert!(findings(&scan(compliant), "python:S6243").is_empty());
    }

    #[test]
    fn s6243_ignores_unrelated_calls_inside_handlers() {
        let compliant = concat!(
            "import boto3\n",
            "def lambda_handler(event, context):\n",
            "    print(event)\n",
            "    other.client('s3')\n",
        );
        assert!(findings(&scan(compliant), "python:S6243").is_empty());
    }
}
