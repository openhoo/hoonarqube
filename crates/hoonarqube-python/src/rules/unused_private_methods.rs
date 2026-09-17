use crate::engine::file_context::FileContext;
use crate::engine::scope::DefFlavor;
use crate::engine::scope::FileFacts;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::name_used_in_tokens;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

// --- python:S1144 — unused private methods -----------------------------------

/// The reference `UnreadPrivateMethodsCheck` covers only class-private
/// (`__name`) members; single-underscore names and dunders are out of scope.
fn is_class_private_name(name: &str) -> bool {
    name.starts_with("__") && !name.ends_with("__")
}

/// Decorated methods are exempt unless every decorator is `staticmethod` or
/// `classmethod`, which keep the member a plain private method.
fn has_only_static_decorators(file_ctx: &FileContext, name_range: TextRange) -> bool {
    let Some(function) = file_ctx
        .functions
        .iter()
        .copied()
        .find(|function| function.name.range() == name_range)
    else {
        return false;
    };
    function.decorator_list.iter().all(|decorator| {
        matches!(
            called_name(&decorator.expression),
            Some("staticmethod" | "classmethod")
        )
    })
}

/// The reference skips classes with decorators entirely: their final member
/// behavior cannot be analyzed.
fn owner_class_is_decorated(file_ctx: &FileContext, name_range: TextRange) -> bool {
    file_ctx
        .classes
        .iter()
        .copied()
        .find(|class| {
            class.body.iter().any(
                |stmt| matches!(stmt, Stmt::FunctionDef(function) if function.name.range() == name_range),
            )
        })
        .is_some_and(|class| !class.decorator_list.is_empty())
}

pub(crate) fn check_unused_private_methods(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Function
            || !matches!(table.scopes[site.enclosing_scope].kind, ScopeKind::Class)
            || !is_class_private_name(&site.name)
        {
            continue;
        }
        if site.decorated && !has_only_static_decorators(file_ctx, site.name_range) {
            continue;
        }
        if owner_class_is_decorated(file_ctx, site.name_range) {
            continue;
        }
        let referenced = facts.attr_reads.iter().any(|(attr, _)| attr == &site.name)
            || facts.called_names.contains(&site.name)
            || facts
                .string_texts
                .iter()
                .any(|text| text.contains(&site.name))
            || name_used_in_tokens(facts, &site.name, &[site.name_range]);
        if !referenced {
            issues.push(issue_at(
                "python:S1144",
                &format!("Remove this unused class-private '{}' method.", site.name),
                site.name_range,
                index,
                source,
            ));
        }
    }
    issues
}
