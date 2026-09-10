use crate::engine::scope::{
    BindingKind, FileFacts, ScopeKind, SymbolTable, scope_has_dynamic_declaration,
};
use crate::support::{for_each_stmt, for_each_stmt_expr, is_builtin_name, issue_at, to_range};
use hoonarqube_ir::{Fix, FixAlternative, Issue, TextEdit};
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// --- python:S5806 — shadowed builtins ----------------------------------------
pub(crate) fn check_shadowed_builtins(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let supported = supported_assignment_ranges(parsed);
    let mut issues = Vec::new();
    for (scope_index, scope) in table.scopes.iter().enumerate() {
        if scope.kind != ScopeKind::Function {
            continue;
        }
        for (name, bindings) in &scope.bindings {
            if !is_builtin_name(name)
                || scope_has_dynamic_declaration(scope, name)
                || facts.dynamic_names
            {
                continue;
            }
            let Some(binding) = bindings
                .iter()
                .find(|b| b.kind == BindingKind::Assignment && supported.contains(&b.range))
            else {
                continue;
            };
            let mut issue = issue_at(
                "python:S5806",
                "Rename this variable; it shadows a builtin.",
                binding.range,
                index,
                source,
            );
            issue.alternatives = alternatives_for_binding(
                table,
                scope_index,
                name,
                binding.range,
                &supported,
                facts,
                &AlternativeContext { index, source },
            );
            issues.push(issue);
        }
    }
    issues
}

fn supported_assignment_ranges(parsed: &Parsed<ModModule>) -> Vec<TextRange> {
    let mut ranges = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                target_ranges(target, &mut ranges);
            }
        }
        Stmt::AnnAssign(assign) if assign.value.is_some() => {
            target_ranges(&assign.target, &mut ranges);
        }
        _ => {}
    });
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Named(named) = expr {
            target_ranges(&named.target, &mut ranges);
        }
    });
    ranges.sort_by_key(Ranged::start);
    ranges.dedup();
    ranges
}
fn target_ranges(expr: &Expr, ranges: &mut Vec<TextRange>) {
    match expr {
        Expr::Name(name) => ranges.push(name.range()),
        Expr::Tuple(tuple) => {
            for elt in &tuple.elts {
                target_ranges(elt, ranges);
            }
        }
        Expr::List(list) => {
            for elt in &list.elts {
                target_ranges(elt, ranges);
            }
        }
        Expr::Starred(starred) => target_ranges(&starred.value, ranges),
        _ => {}
    }
}

pub(crate) struct AlternativeContext<'a> {
    index: &'a LineIndex,
    source: &'a str,
}

pub(crate) fn alternatives_for_binding(
    table: &SymbolTable,
    scope_index: usize,
    name: &str,
    binding_range: TextRange,
    supported: &[TextRange],
    facts: &FileFacts,
    context: &AlternativeContext<'_>,
) -> Vec<FixAlternative> {
    let Some(scope) = table.scopes.get(scope_index) else {
        return Vec::new();
    };
    let replacement_name = format!("_{name}");
    if scope.kind != ScopeKind::Function
        || scope_has_dynamic_declaration(scope, name)
        || facts.dynamic_names
    {
        return Vec::new();
    }
    let Some(bindings) = scope.bindings.get(name) else {
        return Vec::new();
    };
    if !bindings.iter().any(|b| {
        b.kind == BindingKind::Assignment
            && b.range == binding_range
            && supported.contains(&b.range)
    }) {
        return Vec::new();
    }
    if bindings.iter().any(|b| b.kind != BindingKind::Assignment) {
        return Vec::new();
    }
    for (idx, candidate) in table.scopes.iter().enumerate() {
        if !is_descendant(table, idx, scope_index) {
            continue;
        }
        if candidate.bindings.contains_key(&replacement_name)
            || candidate.declares_global(&replacement_name)
            || candidate.declares_nonlocal(name)
        {
            return Vec::new();
        }
    }
    let mut parent = scope.parent;
    while let Some(idx) = parent {
        if table.scopes[idx].bindings.contains_key(&replacement_name) {
            return Vec::new();
        }
        parent = table.scopes[idx].parent;
    }
    if table.resolved_loads.iter().any(|load| {
        load.scope == scope_index
            && load.name == replacement_name
            && load.target != Some(scope_index)
    }) {
        return Vec::new();
    }
    let mut ranges: Vec<TextRange> = bindings
        .iter()
        .filter(|b| b.kind == BindingKind::Assignment && supported.contains(&b.range))
        .map(|b| b.range)
        .collect();
    ranges.extend(
        table
            .resolved_loads
            .iter()
            .filter(|load| load.target == Some(scope_index) && load.name == name)
            .map(|load| load.range),
    );
    ranges.sort_by_key(Ranged::start);
    ranges.dedup();
    if ranges.is_empty() {
        return Vec::new();
    }
    let edits = ranges
        .into_iter()
        .map(|range| TextEdit {
            range: to_range(range, context.index, context.source),
            replacement: replacement_name.clone(),
        })
        .collect();
    vec![FixAlternative {
        id: "s5806-rename-builtin-shadow".to_string(),
        fix: Fix {
            message: format!("Rename to _ {name}"),
            edits,
        },
    }]
}
fn is_descendant(table: &SymbolTable, mut child: usize, ancestor: usize) -> bool {
    loop {
        if child == ancestor {
            return true;
        }
        let Some(parent) = table.scopes[child].parent else {
            return false;
        };
        child = parent;
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};
    #[test]
    fn s5806_rename_alternative_rewrites_all_resolved_usages() {
        let source = "def process(items):\n    len = len(items)\n    return len\n";
        let report = scan(source);
        let issues = findings(&report, "python:S5806");
        assert_eq!(issues.len(), 1);
        let alternative = &issues[0].alternatives[0];
        assert_eq!(alternative.fix.edits.len(), 3);
    }
    #[test]
    fn s5806_valid_assignment_has_rename_alternative() {
        let source = "def process(items):\n    len = 42\n    return len\n";
        let report = scan(source);
        let issues = findings(&report, "python:S5806");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].alternatives[0].fix.edits.len(), 2);
    }
    #[test]
    fn s5806_collision_keeps_finding_fixless() {
        let report = scan("def process(_len):\n    len = 42\n    return len\n");
        let issues = findings(&report, "python:S5806");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].alternatives.is_empty());
    }
    #[test]
    fn s5806_module_level_preassignment_is_not_reported() {
        let report = scan("len = 42\n");
        assert!(findings(&report, "python:S5806").is_empty());
    }
}
