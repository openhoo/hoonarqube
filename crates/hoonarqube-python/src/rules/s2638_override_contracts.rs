use crate::engine::calls::method_shape;
use crate::engine::calls::s2638_contract_change;
use crate::support::direct_base_names;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::module_classes;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S2638 — compares file-local overrides against the direct file-local
/// base declaration; pairs guarded by property-family decorators or differing
/// static-method modifiers are exempt.
pub(crate) fn check_s2638_override_contracts(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let module = parsed.syntax().body.as_slice();
    let classes = module_classes(module);
    let mut issues = Vec::new();
    for stmt in module {
        let Stmt::ClassDef(class) = stmt else {
            continue;
        };
        for base_name in direct_base_names(class) {
            let Some(base) = classes.get(base_name) else {
                continue;
            };
            for member in &class.body {
                let Stmt::FunctionDef(override_method) = member else {
                    continue;
                };
                let method_name = override_method.name.as_str();
                let Some(Stmt::FunctionDef(base_method)) = base.body.iter().find(|candidate| {
                    matches!(candidate, Stmt::FunctionDef(function)
                        if function.name.as_str() == method_name)
                }) else {
                    continue;
                };
                if is_property_family(base_method)
                    || is_property_family(override_method)
                    || has_decorator(base_method, "staticmethod")
                        != has_decorator(override_method, "staticmethod")
                {
                    continue;
                }
                let shapes = (
                    method_shape(base_method, source),
                    method_shape(override_method, source),
                );
                let Some(reason) = s2638_contract_change(&shapes.0, &shapes.1) else {
                    continue;
                };
                issues.push(issue_at(
                    "python:S2638",
                    &format!(
                        "This override of '{base_name}.{method_name}' changes its contract: \
                         {reason}."
                    ),
                    override_method.name.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

// --- migrated from support/mod.rs (S2638) ---
// --- python:S2638 — method overrides should not change contracts --------------

/// Decorators whose paired accessors legitimately differ between overrides.
const PROPERTY_FAMILY_DECORATORS: [&str; 5] =
    ["property", "setter", "getter", "deleter", "cachedproperty"];

fn is_property_family(function: &ruff_python_ast::StmtFunctionDef) -> bool {
    PROPERTY_FAMILY_DECORATORS
        .iter()
        .any(|name| has_decorator(function, name))
}
