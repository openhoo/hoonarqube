use crate::engine::calls::concrete_hint;
use crate::engine::calls::hint_accepts_literal;
use crate::engine::file_context::FileContext;
use crate::engine::project_context::{
    GraphqlResolver, PythonProjectContext, build_current_module_facts,
};
use crate::support::expr_normalized_text;
use crate::support::for_each_return_in_scope;
use crate::support::issue_at;
use crate::support::typed_literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5886 — return types should be consistent with the hint ----------

/// python:S5886 — reports literals and constructors whose resolved type
/// provably contradicts the containing function's annotation.
pub(crate) fn check_s5886_return_hint_mismatches(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    module_name: &str,
    project: &PythonProjectContext,
) -> Vec<Issue> {
    let module = build_current_module_facts(module_name, file_ctx.parsed, project);
    let resolver = GraphqlResolver::new(&module, project);
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::FunctionDef(function) = stmt else {
            continue;
        };
        let Some(annotation) = function.returns.as_deref() else {
            continue;
        };
        let hint = concrete_hint(annotation);
        let annotation_text = expr_normalized_text(annotation, source);
        for_each_return_in_scope(&function.body, &mut |returned| {
            let Some(value) = returned.value.as_deref() else {
                return;
            };
            let actual_type = literal_mismatch_type(hint, value)
                .or_else(|| resolver.incompatible_constructor_type(annotation, value));
            let Some(actual_type) = actual_type else {
                return;
            };
            issues.push(issue_at(
                "python:S5886",
                &format!(
                    "Return a value of type \"{annotation_text}\" instead of \"{actual_type}\" or update function \"{}\" type hint.",
                    function.name.as_str()
                ),
                value.range(),
                index,
                source,
            ));
        });
    }
    issues
}

fn literal_mismatch_type(
    hint: Option<crate::engine::calls::HintKind>,
    value: &ruff_python_ast::Expr,
) -> Option<String> {
    let hint = hint?;
    let kind = typed_literal_kind(value)?;
    if hint_accepts_literal(hint, kind) {
        return None;
    }
    Some(
        match kind {
            "string" => "str",
            "boolean" => "bool",
            "none" => "None",
            other => other,
        }
        .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use crate::PythonProjectContext;
    use crate::test_support::{findings, scan, scan_in_project};
    use std::path::PathBuf;

    #[test]
    fn nominal_returns_follow_relative_imports_and_ancestry() {
        let mut project = PythonProjectContext::new();
        project.add_module(
            "pkg.responses",
            "class Response: pass\nclass Child(Response): pass\n",
        );
        project.add_module("pkg.errors", "class HTTPError(Exception): pass\nclass BadRequest(HTTPError): pass\nclass SecurityError(BadRequest): pass\n");
        project.add_module(
            "pkg.exports",
            "from .responses import Response as Exported\n",
        );
        let report = scan_in_project(
            &project,
            PathBuf::from("pkg/views.py"),
            concat!(
                "from .exports import Exported as Response\n",
                "from .responses import Child\n",
                "from .errors import SecurityError as Problem\n",
                "def bad() -> Response:\n    return Problem()\n",
                "def good() -> Response:\n    return Child()\n",
                "def exact() -> Response:\n    return Response()\n",
            ),
        );
        let issues = findings(&report, "python:S5886");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Return a value of type \"Response\" instead of \"SecurityError\" or update function \"bad\" type hint."
        );
        assert_eq!(issues[0].range.start.line, 5);
        assert_eq!(issues[0].range.start.column, 11);
        assert_eq!(issues[0].range.end.column, 20);
    }

    #[test]
    fn package_initializers_resolve_relative_imports_from_the_package() {
        let source = concat!(
            "from ..responses import Response\n",
            "from ..errors import Problem\n",
            "class Views:\n",
            "    def bad(self) -> Response:\n        return Problem()\n",
        );
        let mut project = PythonProjectContext::new();
        project.add_path("pkg/responses.py", "class Response: pass\n");
        project.add_path("pkg/errors.py", "class Problem(Exception): pass\n");
        project.add_path("pkg/views/__init__.py", source);
        let report = scan_in_project(&project, PathBuf::from("pkg/views/__init__.py"), source);
        let issues = findings(&report, "python:S5886");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].range.start.line, 5);
        assert!(issues[0].message.contains("instead of \"Problem\""));
    }

    #[test]
    fn unresolved_dynamic_and_shadowed_constructors_remain_unknown() {
        let report = scan(concat!(
            "class Response: pass\n",
            "class MissingBase(Unknown): pass\n",
            "class Dynamic(factory()): pass\n",
            "def unknown() -> Response:\n    return MissingBase()\n",
            "def dynamic() -> Response:\n    return Dynamic()\n",
            "def shadow(Response, factory) -> Response:\n    return factory()\n",
            "class Child(Response): pass\n",
            "def nested() -> Response:\n",
            "    def inner() -> int:\n        return 1\n",
            "    return Child()\n",
        ));
        assert!(findings(&report, "python:S5886").is_empty());
    }
}
