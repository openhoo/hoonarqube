// --- python:S5906 / python:S5914 — imprecise and unconditional asserts

use crate::support::{
    called_name, child_bodies, child_exprs, collect_module_literal_bindings, constant_truth,
    stmt_exprs,
};
use ruff_python_ast::{Expr, ExprCall, ModModule, Pattern, Stmt};
use ruff_python_parser::Parsed;
use ruff_text_size::{Ranged, TextRange};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Module-level, one-write literal facts used by S5914.
///
/// `collect_module_literal_bindings` rejects reassignment and any other
/// additional write (including writes in branches and nested scopes). Because
/// its generic write inventory does not include exception aliases or match
/// captures, those names are conservatively removed from the candidate set.
/// Calls inside functions/classes are intentionally not resolved against these
/// facts, so parameters and local shadowing remain unknown.
pub(crate) struct UnconditionalAssertFacts {
    module_calls: BTreeMap<(u32, u32), Option<bool>>,
}
#[derive(Clone, Copy)]
enum ModuleTruth {
    Unrecognized,
    Unknown,
    Known(bool),
}

impl UnconditionalAssertFacts {
    pub(crate) fn build(parsed: &Parsed<ModModule>) -> Self {
        let module = parsed.syntax().body.as_slice();
        let mut candidates = collect_module_literal_bindings(module);
        let mut untracked_names = HashSet::new();
        collect_untracked_module_writes(module, &mut untracked_names);
        for name in untracked_names {
            candidates.remove(&name);
        }
        let mut bindings: HashMap<String, (TextRange, bool)> = HashMap::new();
        for statement in module {
            let Stmt::Assign(assign) = statement else {
                continue;
            };
            let [Expr::Name(name)] = assign.targets.as_slice() else {
                continue;
            };
            if !candidates.contains(name.id.as_str()) {
                continue;
            }
            let Some(truth) = constant_truth(&assign.value) else {
                continue;
            };
            bindings.insert(name.id.as_str().to_string(), (statement.range(), truth));
        }

        let mut module_calls = BTreeMap::new();
        for_each_module_stmt_expr(module, &mut |expr| {
            let Expr::Call(call) = expr else {
                return;
            };
            if !is_unconditional_assertion(call) {
                return;
            }
            let truth = call.arguments.args.first().and_then(|argument| {
                constant_truth(argument).or_else(|| {
                    let Expr::Name(name) = argument else {
                        return None;
                    };
                    bindings.get(name.id.as_str()).and_then(|(range, truth)| {
                        (range.end() <= call.range().start()).then_some(*truth)
                    })
                })
            });
            module_calls.insert(range_key(call.range()), truth);
        });
        Self { module_calls }
    }

    fn module_truth(&self, call: &ExprCall) -> ModuleTruth {
        match self.module_calls.get(&range_key(call.range())).copied() {
            None => ModuleTruth::Unrecognized,
            Some(None) => ModuleTruth::Unknown,
            Some(Some(truth)) => ModuleTruth::Known(truth),
        }
    }
}

fn range_key(range: TextRange) -> (u32, u32) {
    (u32::from(range.start()), u32::from(range.end()))
}

fn collect_untracked_module_writes(statements: &[Stmt], names: &mut HashSet<String>) {
    for statement in statements {
        match statement {
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => continue,
            Stmt::Try(try_stmt) => {
                for handler in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
                    if let Some(name) = &handler.name {
                        names.insert(name.as_str().to_string());
                    }
                }
            }
            Stmt::Match(match_stmt) => {
                for case in &match_stmt.cases {
                    collect_pattern_capture_names(&case.pattern, names);
                }
            }
            _ => {}
        }
        for body in child_bodies(statement) {
            collect_untracked_module_writes(body, names);
        }
    }
}

fn collect_pattern_capture_names(pattern: &Pattern, names: &mut HashSet<String>) {
    let mut pending = vec![pattern];
    while let Some(pattern) = pending.pop() {
        match pattern {
            Pattern::MatchSequence(sequence) => pending.extend(&sequence.patterns),
            Pattern::MatchMapping(mapping) => {
                pending.extend(&mapping.patterns);
                if let Some(rest) = &mapping.rest {
                    names.insert(rest.as_str().to_string());
                }
            }
            Pattern::MatchClass(class) => {
                pending.extend(&class.arguments.patterns);
                pending.extend(
                    class
                        .arguments
                        .keywords
                        .iter()
                        .map(|keyword| &keyword.pattern),
                );
            }
            Pattern::MatchStar(star) => {
                if let Some(name) = &star.name {
                    names.insert(name.as_str().to_string());
                }
            }
            Pattern::MatchAs(as_pattern) => {
                pending.extend(as_pattern.pattern.as_deref());
                if let Some(name) = &as_pattern.name {
                    names.insert(name.as_str().to_string());
                }
            }
            Pattern::MatchOr(or_pattern) => pending.extend(&or_pattern.patterns),
            Pattern::MatchValue(_) | Pattern::MatchSingleton(_) => {}
        }
    }
}

/// Visits expressions in module/control-flow scopes without entering a
/// function, class, lambda, or comprehension scope.
fn for_each_module_stmt_expr<'a>(statements: &'a [Stmt], visit: &mut impl FnMut(&'a Expr)) {
    for statement in statements {
        if matches!(statement, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        for expression in stmt_exprs(statement) {
            for_each_module_expr(expression, visit);
        }
        for body in child_bodies(statement) {
            for_each_module_stmt_expr(body, visit);
        }
    }
}

fn for_each_module_expr<'a>(expression: &'a Expr, visit: &mut impl FnMut(&'a Expr)) {
    if matches!(
        expression,
        Expr::Lambda(_)
            | Expr::ListComp(_)
            | Expr::SetComp(_)
            | Expr::Generator(_)
            | Expr::DictComp(_)
    ) {
        return;
    }
    visit(expression);
    for child in child_exprs(expression) {
        for_each_module_expr(child, visit);
    }
}

pub(crate) fn unconditional_assert_verdict(call: &ExprCall, _source: &str) -> Option<&'static str> {
    verdict_for_truth(call, call.arguments.args.first().and_then(constant_truth))
}

pub(crate) fn unconditional_assert_verdict_with_facts(
    call: &ExprCall,
    source: &str,
    facts: &UnconditionalAssertFacts,
) -> Option<&'static str> {
    match facts.module_truth(call) {
        ModuleTruth::Known(truth) => verdict_for_truth(call, Some(truth)),
        ModuleTruth::Unknown => None,
        ModuleTruth::Unrecognized => unconditional_assert_verdict(call, source),
    }
}

fn is_unconditional_assertion(call: &ExprCall) -> bool {
    call.arguments.args.len() == 1
        && matches!(called_name(&call.func), Some("assertTrue" | "assertFalse"))
}

fn verdict_for_truth(call: &ExprCall, truth: Option<bool>) -> Option<&'static str> {
    if call.arguments.args.len() != 1 {
        return None;
    }
    let truth = truth?;
    match (called_name(&call.func), truth) {
        (Some("assertTrue"), true) | (Some("assertFalse"), false) => Some("passes"),
        (Some("assertTrue"), false) | (Some("assertFalse"), true) => Some("fails"),
        _ => None,
    }
}
