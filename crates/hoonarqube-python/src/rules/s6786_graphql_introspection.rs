use crate::engine::file_context::FileContext;
use crate::engine::project_context::{
    GraphqlResolver, GraphqlSafety, PythonProjectContext, SymbolResolution, build_module_facts,
};
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
const MESSAGE: &str = "Disable introspection on this \"GraphQL\" server endpoint.";

/// Checks GraphQL Flask view factories using only resolved framework symbols.
///
/// The reference `SonarPython` helper reports a call when both `middleware`
/// and `validation_rules` are absent or are known list, tuple, or set values
/// without a recognized blocker.  Non-collection or unresolved values remain
/// explicit `Unknown` and suppress this finding exactly as the reference
/// helper does; callers that need semantic completeness can inspect the
/// project-context resolver state separately.
pub(crate) fn check_s6786_graphql_introspection(
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

        let middleware = keyword_value(call, "middleware")
            .map_or(GraphqlSafety::Unsafe, |expression| {
                resolver.configuration_safety(scope, call.start(), expression)
            });
        let validation_rules = keyword_value(call, "validation_rules")
            .map_or(GraphqlSafety::Unsafe, |expression| {
                resolver.configuration_safety(scope, call.start(), expression)
            });

        // Unknown is not a claimed safe configuration, but preserving the
        // reference helper's non-list shortcut means only two proven unsafe
        // collection/absence results produce an S6786 finding.
        if middleware == GraphqlSafety::Unsafe && validation_rules == GraphqlSafety::Unsafe {
            issues.push(issue_at(
                "python:S6786",
                MESSAGE,
                callee.range(),
                index,
                source,
            ));
        }
    }
    issues
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
    use super::*;
    use crate::test_support::{findings, scan, scan_in_project};
    use std::path::PathBuf;

    #[test]
    fn direct_framework_import_flags_missing_blockers_and_accepts_known_rules() {
        let source = concat!(
            "from flask_graphql import GraphQLView\n",
            "GraphQLView.as_view(schema=schema)\n",
            "GraphQLView.as_view(schema=schema, middleware=[])\n",
            "GraphQLView.as_view(schema=schema, middleware=[IntrospectionMiddleware])\n",
            "GraphQLView.as_view(schema=schema, validation_rules=[NoSchemaIntrospectionCustomRule])\n",
        );
        let report = scan(source);
        assert_eq!(findings(&report, "python:S6786").len(), 2);
    }

    #[test]
    fn second_supported_graphql_server_import_is_resolved() {
        let source = concat!(
            "from graphql_server.flask import GraphQLView as View\n",
            "View.as_view(schema=schema)\n",
            "View.as_view(schema=schema, validation_rules=[graphene.validation.DisableIntrospection])\n",
        );
        let report = scan(source);
        assert_eq!(findings(&report, "python:S6786").len(), 1);
    }

    #[test]
    fn set_literals_follow_the_collection_blocker_contract() {
        let source = concat!(
            "from flask_graphql import GraphQLView\n",
            "GraphQLView.as_view(schema=schema, middleware={some_middleware})\n",
            "GraphQLView.as_view(schema=schema, middleware={IntrospectionMiddleware})\n",
            "GraphQLView.as_view(schema=schema, validation_rules={NoSchemaIntrospectionCustomRule})\n",
        );
        assert_eq!(findings(&scan(source), "python:S6786").len(), 1);
    }

    #[test]
    fn collection_alias_chains_are_resolved_before_safety_is_classified() {
        let source = concat!(
            "from flask_graphql import GraphQLView\n",
            "from graphene.validation import DisableIntrospection\n",
            "rules = [DisableIntrospection]\n",
            "alias = rules\n",
            "GraphQLView.as_view(schema=schema, validation_rules=alias)\n",
        );
        assert!(findings(&scan(source), "python:S6786").is_empty());
    }

    #[test]
    fn module_aliases_keep_their_defining_scope_when_locals_shadow_names() {
        let source = concat!(
            "from flask_graphql import GraphQLView\n",
            "from graphene.validation import DisableIntrospection as SafeRule\n",
            "rules = [SafeRule]\n",
            "def view():\n",
            "    SafeRule = unsafe_rule\n",
            "    alias = rules\n",
            "    GraphQLView.as_view(schema=schema, validation_rules=alias)\n",
        );
        assert!(findings(&scan(source), "python:S6786").is_empty());
    }
    #[test]
    fn cyclic_configuration_aliases_fail_closed_without_recursing() {
        let source = concat!(
            "from flask_graphql import GraphQLView\n",
            "first = second\n",
            "second = first\n",
            "GraphQLView.as_view(schema=schema, middleware=[first])\n",
        );
        assert_eq!(findings(&scan(source), "python:S6786").len(), 1);
    }
    #[test]
    fn aliases_reexports_and_cross_module_subclasses_resolve() {
        let mut project = PythonProjectContext::new();
        project.add_module(
            "framework_alias",
            "from flask_graphql import GraphQLView as BaseView\nExportedView = BaseView\n",
        );
        project.add_module(
            "base",
            "from framework_alias import ExportedView\nclass Base(ExportedView):\n    pass\n",
        );
        let source = concat!(
            "from base import Base as ImportedBase\n",
            "class Derived(ImportedBase):\n",
            "    pass\n",
            "Derived.as_view(schema=schema)\n",
        );
        let report = scan_in_project(&project, PathBuf::from("views.py"), source);
        assert_eq!(findings(&report, "python:S6786").len(), 1);
    }

    #[test]
    fn local_collection_aliases_keep_their_function_scope() {
        let source = concat!(
            "from flask_graphql import GraphQLView\n",
            "from graphene.validation import DisableIntrospection as SafeRule\n",
            "def view():\n",
            "    gql_middlew = [SafeRule]\n",
            "    GraphQLView.as_view(schema=schema, middleware=gql_middlew)\n",
        );
        assert!(findings(&scan(source), "python:S6786").is_empty());
    }

    #[test]
    fn same_named_local_class_is_not_framework_identity() {
        let report = scan(concat!(
            "class GraphQLView:\n",
            "    @classmethod\n",
            "    def as_view(cls, **kwargs):\n",
            "        return None\n",
            "GraphQLView.as_view(schema=schema)\n",
        ));
        assert!(findings(&report, "python:S6786").is_empty());
    }

    #[test]
    fn non_collection_dynamic_configuration_keeps_reference_result_but_is_not_safe_provenance() {
        let source = concat!(
            "from flask_graphql import GraphQLView\n",
            "GraphQLView.as_view(schema=schema, middleware=dynamic_value)\n",
            "GraphQLView.as_view(schema=schema, validation_rules=build_rules())\n",
        );
        assert!(findings(&scan(source), "python:S6786").is_empty());
    }
}
