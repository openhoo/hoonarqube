use crate::engine::file_context::FileContext;
use crate::engine::scope::BindingKind;
use crate::support::WebFrameworkFacts;
use crate::support::function_parameters;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_typevar_annotated_functions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let table = file_ctx.symbol_table();
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        let Some(site) = table
            .def_sites
            .iter()
            .find(|site| site.name_range == function.name.range())
        else {
            continue;
        };
        let annotations = function_parameters(function)
            .into_iter()
            .filter_map(|parameter| parameter.parameter.annotation.as_deref())
            .chain(
                function
                    .parameters
                    .vararg
                    .as_deref()
                    .and_then(|parameter| parameter.annotation.as_deref()),
            )
            .chain(
                function
                    .parameters
                    .kwarg
                    .as_deref()
                    .and_then(|parameter| parameter.annotation.as_deref()),
            )
            .chain(function.returns.as_deref());
        let flagged = annotations.into_iter().any(|annotation| {
            let Expr::Name(name) = annotation else {
                return false;
            };
            // A function's signature is evaluated in its defining scope, not
            // the new body scope, even when a parameter shadows this name.
            let mut scope = Some(site.enclosing_scope);
            while let Some(current) = scope {
                let symbols = &table.scopes[current];
                if let Some(bindings) = symbols.bindings.get(name.id.as_str()) {
                    let [binding] = bindings.as_slice() else {
                        return false;
                    };
                    if binding.kind != BindingKind::Assignment {
                        return false;
                    }
                    let Some(Expr::Call(call)) =
                        file_ctx.assigned_values().get(&binding.range).copied()
                    else {
                        return false;
                    };
                    return facts.expr_fqn(&call.func).as_deref() == Some("typing.TypeVar");
                }
                scope = symbols.parent;
            }
            false
        });
        if flagged {
            issues.push(issue_at(
                "python:S6796",
                "Use a generic type parameter for this function instead of a \"TypeVar\".",
                function.name.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6796_prefers_pep695_parameters_over_typevar_hints() {
        let flagged = scan(concat!(
            "from typing import TypeVar\n",
            "T = TypeVar(\"T\")\n",
            "def identity(x: T) -> T:\n",
            "    return x\n",
            "def plain(x: int) -> int:\n",
            "    return x\n"
        ));
        assert_eq!(findings(&flagged, "python:S6796").len(), 1);
    }
    #[test]
    fn remaining_s6796_requires_direct_annotations_and_typing_provenance() {
        let report = scan(concat!(
            "from typing import TypeVar as TV\n",
            "T = TV('T')\n",
            "def direct(T: T) -> T:\n    return T\n",
            "def compound(x: list[T]) -> T | None:\n    return None\n",
            "def variadic(**kwargs: T):\n    return kwargs\n",
            "def outer():\n",
            "    T = int\n",
            "    def shadowed(x: T):\n        return x\n",
            "class TypeVar:\n    pass\n",
            "F = TypeVar()\n",
            "def fake(x: F):\n    return x\n",
            "R = TV('R')\nR = int\n",
            "def rebound(x: R):\n    return x\n",
        ));
        let issues = findings(&report, "python:S6796");
        assert_eq!(issues.len(), 2);
        for issue in issues {
            assert_eq!(
                issue.message,
                "Use a generic type parameter for this function instead of a \"TypeVar\"."
            );
        }
    }
}
