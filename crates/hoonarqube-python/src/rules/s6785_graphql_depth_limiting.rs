use crate::engine::file_context::FileContext;
use crate::engine::project_context::{
    GraphqlResolver, PythonProjectContext, SymbolResolution, build_module_facts,
};
use crate::support::{is_zero_literal, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6785 — GraphQL endpoints vulnerable to DoS ------------------------
//
// The documented owning API is the framework's GraphQLView.as_view endpoint.
// A finding is emitted only for a file containing a provenance-resolved
// SQLAlchemy-backed relationship and a provenance-resolved GraphQLView call
// whose validation_rules argument is absent or a known collection without the
// provenance-resolved Graphene depth validator.  Schema construction and
// unrelated graphql.validate calls are intentionally outside this rule.

const MESSAGE: &str = "Change this code to limit the depth of GraphQL queries.";

pub(crate) fn check_s6785_graphql_depth_limiting(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    module_name: &str,
    project: &PythonProjectContext,
) -> Vec<Issue> {
    if !parsed.errors().is_empty() {
        return Vec::new();
    }
    let module = build_module_facts(module_name, parsed);
    let resolver = GraphqlResolver::new(&module, project);
    let has_sqlalchemy_relationship = file_ctx.calls.iter().any(|call| {
        let Expr::Attribute(callee) = call.func.as_ref() else {
            return false;
        };
        if callee.attr.as_str() != "relationship" {
            return false;
        }
        let Expr::Name(receiver) = callee.value.as_ref() else {
            return false;
        };
        let relationship_scope = module.scope_at(call.start());
        resolver.is_single_assigned_sqlalchemy_constructor(
            relationship_scope,
            call.start(),
            receiver.id.as_str(),
        )
    });
    if !has_sqlalchemy_relationship {
        return Vec::new();
    }

    let mut issues = Vec::new();

    for call in &file_ctx.calls {
        let Expr::Attribute(callee) = call.func.as_ref() else {
            continue;
        };
        if callee.attr.as_str() != "as_view" {
            continue;
        }
        let scope = module.scope_at(call.start());
        if resolver.resolve_expression(scope, call.start(), callee.value.as_ref())
            != SymbolResolution::GraphqlView
        {
            continue;
        }
        if depth_rules_safety(keyword_value(call, "validation_rules"), &resolver, scope)
            == DepthRulesSafety::Unsafe
        {
            issues.push(issue_at(
                "python:S6785",
                MESSAGE,
                callee.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DepthRulesSafety {
    Safe,
    Unsafe,
    Unknown,
}

fn depth_rules_safety(
    expression: Option<&Expr>,
    resolver: &GraphqlResolver<'_>,
    scope: usize,
) -> DepthRulesSafety {
    let Some(expression) = expression else {
        return DepthRulesSafety::Unsafe;
    };
    match expression {
        Expr::List(list) => collection_has_depth_validator(&list.elts, resolver, scope),
        Expr::Tuple(tuple) => collection_has_depth_validator(&tuple.elts, resolver, scope),
        Expr::Set(set) => collection_has_depth_validator(&set.elts, resolver, scope),
        // Multiplication by a known zero discards the validator at runtime;
        // textual presence in the left operand is not a depth-limit proof.
        Expr::BinOp(binary)
            if binary.op == ruff_python_ast::Operator::Mult
                && (is_zero_literal(binary.left.as_ref())
                    || is_zero_literal(binary.right.as_ref())) =>
        {
            DepthRulesSafety::Unsafe
        }
        _ => DepthRulesSafety::Unknown,
    }
}

fn collection_has_depth_validator(
    elements: &[Expr],
    resolver: &GraphqlResolver<'_>,
    scope: usize,
) -> DepthRulesSafety {
    if elements
        .iter()
        .any(|element| is_owned_depth_validator(element, resolver, scope))
    {
        DepthRulesSafety::Safe
    } else {
        DepthRulesSafety::Unsafe
    }
}

fn is_owned_depth_validator(
    expression: &Expr,
    resolver: &GraphqlResolver<'_>,
    scope: usize,
) -> bool {
    let Expr::Call(call) = expression else {
        return false;
    };
    resolver.resolve_expression(scope, call.start(), call.func.as_ref())
        == SymbolResolution::GraphqlDepthValidator
}

fn keyword_value<'a>(call: &'a ExprCall, wanted: &str) -> Option<&'a Expr> {
    call.arguments.keywords.iter().find_map(|keyword| {
        keyword
            .arg
            .as_ref()
            .filter(|name| name.as_str() == wanted)
            .map(|_| &keyword.value)
    })
}

#[cfg(test)]
mod tests {
    use crate::PythonProjectContext;
    use crate::test_support::{findings, scan, scan_in_project};
    use std::path::PathBuf;

    #[test]
    fn s6785_requires_an_owned_relationship_before_checking_depth_limiting() {
        let graphene_only = concat!(
            "from graphql_server.flask import GraphQLView\n",
            "GraphQLView.as_view(schema=schema)\n",
        );
        assert!(findings(&scan(graphene_only), "python:S6785").is_empty());

        let graphene_only_with_validator = concat!(
            "from graphene.validation import depth_limit_validator\n",
            "from graphql_server.flask import GraphQLView\n",
            "GraphQLView.as_view(\n",
            "    schema=schema,\n",
            "    validation_rules=[depth_limit_validator(10)],\n",
            ")\n",
        );
        assert!(findings(&scan(graphene_only_with_validator), "python:S6785").is_empty());
        let attack = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphql_server.flask import GraphQLView\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "\n",
            "GraphQLView.as_view(schema=schema)\n",
        );
        let report = scan(attack);
        let found = findings(&report, "python:S6785");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Change this code to limit the depth of GraphQL queries."
        );

        let safe = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphene.validation import depth_limit_validator\n",
            "from graphql_server.flask import GraphQLView\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "GraphQLView.as_view(\n",
            "    schema=schema,\n",
            "    validation_rules=[depth_limit_validator(10)],\n",
            ")\n",
        );
        assert!(findings(&scan(safe), "python:S6785").is_empty());
    }

    #[test]
    fn s6785_requires_the_supported_graphql_view_identity() {
        let local_view = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphql_server.flask import GraphQLView\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "\n",
            "class GraphQLView:\n",
            "    @classmethod\n",
            "    def as_view(cls, **kwargs):\n",
            "        return None\n",
            "\n",
            "GraphQLView.as_view(schema=schema)\n",
        );
        assert!(findings(&scan(local_view), "python:S6785").is_empty());

        let schema_constructor = concat!(
            "from graphene import Schema\n",
            "from flask_sqlalchemy import SQLAlchemy\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "schema = Schema(query=Query)\n",
        );
        assert!(findings(&scan(schema_constructor), "python:S6785").is_empty());
    }

    #[test]
    fn s6785_resolves_an_imported_depth_validator_for_the_endpoint() {
        let mut project = PythonProjectContext::new();
        project.add_module(
            "depth_rules",
            "from graphene.validation import depth_limit_validator\n",
        );
        let source = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphql_server.flask import GraphQLView\n",
            "from depth_rules import depth_limit_validator\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "GraphQLView.as_view(\n",
            "    schema=schema,\n",
            "    validation_rules=[depth_limit_validator(10)],\n",
            ")\n",
        );
        let report = scan_in_project(&project, PathBuf::from("schema.py"), source);
        assert!(findings(&report, "python:S6785").is_empty());
    }

    #[test]
    fn s6785_does_not_report_cross_file_depth_limiter_on_unowned_validate_call() {
        let mut project = PythonProjectContext::new();
        project.add_module(
            "depth_rules",
            "from graphene.validation import depth_limit_validator\n",
        );
        let source = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphene import Schema\n",
            "from graphql import parse, specified_rules, validate\n",
            "from depth_rules import depth_limit_validator\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "schema = Schema(query=Query)\n",
            "parsed_document = parse(document_text)\n",
            "errors = validate(\n",
            "    schema.graphql_schema,\n",
            "    parsed_document,\n",
            "    rules=specified_rules + (depth_limit_validator(10),),\n",
            ")\n",
        );
        let report = scan_in_project(&project, PathBuf::from("schema.py"), source);
        assert!(findings(&report, "python:S6785").is_empty());
    }

    #[test]
    fn s6785_does_not_accept_discarded_or_unrelated_depth_validation() {
        let discarded = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphene.validation import depth_limit_validator\n",
            "from graphql_server.flask import GraphQLView\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "GraphQLView.as_view(\n",
            "    schema=schema,\n",
            "    validation_rules=[depth_limit_validator(10)] * 0,\n",
            ")\n",
        );
        assert_eq!(findings(&scan(discarded), "python:S6785").len(), 1);

        let later_validation = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphene import Schema\n",
            "from graphene.validation import depth_limit_validator\n",
            "from graphql import specified_rules, validate\n",
            "from graphql_server.flask import GraphQLView\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "schema = Schema(query=Query)\n",
            "GraphQLView.as_view(schema=schema)\n",
            "validate(schema.graphql_schema, document,\n",
            "         rules=specified_rules + (depth_limit_validator(10),))\n",
        );
        assert_eq!(findings(&scan(later_validation), "python:S6785").len(), 1);
    }

    #[test]
    fn s6785_accepts_actual_imported_sqlalchemy_constructor_aliases() {
        let from_alias = concat!(
            "from flask_sqlalchemy import SQLAlchemy as Database\n",
            "from graphql_server.flask import GraphQLView\n",
            "db = Database()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "GraphQLView.as_view(schema=schema)\n",
        );
        assert_eq!(findings(&scan(from_alias), "python:S6785").len(), 1);

        let module_alias = concat!(
            "import flask_sqlalchemy as flask_sa\n",
            "from graphql_server.flask import GraphQLView\n",
            "db = flask_sa.SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "GraphQLView.as_view(schema=schema)\n",
        );
        assert_eq!(findings(&scan(module_alias), "python:S6785").len(), 1);
    }

    #[test]
    fn s6785_rejects_a_local_sqlalchemy_impostor() {
        let source = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphql_server.flask import GraphQLView\n",
            "def fake_sqlalchemy():\n",
            "    return object()\n",
            "SQLAlchemy = fake_sqlalchemy\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "GraphQLView.as_view(schema=schema)\n",
        );
        assert!(findings(&scan(source), "python:S6785").is_empty());
    }

    #[test]
    fn s6785_rejects_a_multiply_assigned_relationship_receiver() {
        let source = concat!(
            "from flask_sqlalchemy import SQLAlchemy\n",
            "from graphql_server.flask import GraphQLView\n",
            "db = SQLAlchemy()\n",
            "db = SQLAlchemy()\n",
            "class Record(db.Model):\n",
            "    parent = db.relationship(\"Record\")\n",
            "GraphQLView.as_view(schema=schema)\n",
        );
        assert!(findings(&scan(source), "python:S6785").is_empty());
    }
}
