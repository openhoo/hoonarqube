use crate::engine::file_context::FileContext;
use crate::engine::scope::{BindingKind, SymbolTable};
use crate::support::WebFrameworkFacts;
use crate::support::function_parameters;
use crate::support::issue_at;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

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
        let mut uses = Vec::new();
        let mut assignments = Vec::new();
        for annotation in annotations {
            if let Some(assignment) =
                typevar_assignment(annotation, site.enclosing_scope, table, file_ctx, &facts)
            {
                uses.push(annotation.range());
                assignments.push(assignment);
            }
        }
        if !uses.is_empty() {
            let mut issue = issue_at(
                "python:S6796",
                "Use a generic type parameter for this function instead of a \"TypeVar\".",
                function.name.range(),
                index,
                source,
            );
            // The upstream analyzer gathers independent secondary locations
            // in sets. Preserve their contents with a deterministic source
            // order rather than depending on an object's identity hash.
            uses.sort_unstable_by_key(Ranged::start);
            assignments.sort_unstable_by_key(Ranged::start);
            assignments.dedup();
            issue.flows = uses
                .into_iter()
                .map(|range| (range, "Use of \"TypeVar\" here."))
                .chain(
                    assignments
                        .into_iter()
                        .map(|range| (range, "\"TypeVar\" is assigned here.")),
                )
                .map(|(range, message)| hoonarqube_ir::IssueFlow {
                    locations: vec![hoonarqube_ir::FlowLocation::in_primary_file(
                        message,
                        to_range(range, index, source),
                    )],
                })
                .collect();
            issues.push(issue);
        }
    }
    issues
}

fn typevar_assignment(
    annotation: &Expr,
    enclosing_scope: usize,
    table: &SymbolTable,
    file_ctx: &FileContext<'_>,
    facts: &WebFrameworkFacts<'_>,
) -> Option<TextRange> {
    let Expr::Name(name) = annotation else {
        return None;
    };
    // A signature is evaluated in its defining scope, not the new body
    // scope, even when a parameter shadows this name.
    let mut scope = Some(enclosing_scope);
    while let Some(current) = scope {
        let symbols = &table.scopes[current];
        if let Some(bindings) = symbols.bindings.get(name.id.as_str()) {
            let [binding] = bindings.as_slice() else {
                return None;
            };
            if binding.kind != BindingKind::Assignment {
                return None;
            }
            let Expr::Call(call) = file_ctx.assigned_values().get(&binding.range).copied()? else {
                return None;
            };
            return (facts.expr_fqn(&call.func).as_deref() == Some("typing.TypeVar"))
                .then_some(call.range());
        }
        scope = symbols.parent;
    }
    None
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

    #[test]
    fn s6796_secondary_locations_preserve_uses_and_deduplicate_assignments() {
        let report = scan(concat!(
            "from typing import TypeVar as TV\n",
            "T = TV('T')\n",
            "U = TV('U')\n",
            "def identity(x: T, y: U) -> T:\n    return x\n",
            "def outer():\n",
            "    T = int\n",
            "    def shadowed(x: T):\n        return x\n",
            "def compound(x: list[T]):\n    return x\n",
        ));
        let found = findings(&report, "python:S6796");
        assert_eq!(found.len(), 1);
        let locations: Vec<_> = found[0]
            .flows
            .iter()
            .map(|flow| {
                assert_eq!(flow.locations.len(), 1);
                let location = &flow.locations[0];
                assert!(location.path.is_none());
                (
                    location.message.as_str(),
                    location.range.start.line,
                    location.range.start.column,
                    location.range.end.line,
                    location.range.end.column,
                )
            })
            .collect();
        assert_eq!(
            locations,
            vec![
                ("Use of \"TypeVar\" here.", 4, 16, 4, 17),
                ("Use of \"TypeVar\" here.", 4, 22, 4, 23),
                ("Use of \"TypeVar\" here.", 4, 28, 4, 29),
                ("\"TypeVar\" is assigned here.", 2, 4, 2, 11),
                ("\"TypeVar\" is assigned here.", 3, 4, 3, 11),
            ]
        );
    }
}
