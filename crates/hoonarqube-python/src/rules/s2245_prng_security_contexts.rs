use crate::engine::file_context::FileContext;
use crate::support::{
    child_bodies, for_each_expr, for_each_stmt_in_scope, issue_at, stmt_exprs, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};

pub(crate) fn check_s2245_prng_security_contexts(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut module_bindings = ScopeBindings::default();
    visit_scope(
        file_ctx.module_body,
        &mut module_bindings,
        false,
        true,
        index,
        source,
        &mut issues,
    );
    issues
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RandomIdentity {
    Unknown,
    RandomModule,
    RandomFunction,
    RandomClass,
    SystemRandomClass,
    RandomInstance,
    SystemRandomInstance,
}

#[derive(Clone, Default)]
struct ScopeBindings {
    values: HashMap<String, RandomIdentity>,
}

fn visit_scope(
    suite: &[Stmt],
    bindings: &mut ScopeBindings,
    security_context: bool,
    module_scope: bool,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for statement in suite {
        for expression in stmt_exprs(statement) {
            for_each_expr(expression, &mut |expression| {
                if let Expr::Call(call) = expression
                    && (module_scope || security_context)
                    && is_unsafe_random_call(call, bindings)
                {
                    issues.push(issue_at(
                        "python:S2245",
                        "Make sure that using this pseudorandom number generator is safe here.",
                        call.range(),
                        index,
                        source,
                    ));
                }
            });
        }

        match statement {
            Stmt::FunctionDef(function) => {
                let mut child = child_scope(bindings, &function.body, Some(function));
                let security = is_security_context(function.name.as_str());
                visit_scope(
                    &function.body,
                    &mut child,
                    security,
                    false,
                    index,
                    source,
                    issues,
                );
            }
            Stmt::ClassDef(class) => {
                let mut child = child_scope(bindings, &class.body, None);
                visit_scope(&class.body, &mut child, false, false, index, source, issues);
            }
            _ => {
                for body in child_bodies(statement) {
                    visit_scope(
                        body,
                        bindings,
                        security_context,
                        module_scope,
                        index,
                        source,
                        issues,
                    );
                }
            }
        }
        bind_statement(statement, bindings);
    }
}

fn child_scope(
    parent: &ScopeBindings,
    suite: &[Stmt],
    function: Option<&StmtFunctionDef>,
) -> ScopeBindings {
    let mut child = parent.clone();
    let mut locals = HashSet::new();
    for_each_stmt_in_scope(suite, &mut |statement| {
        locals.extend(stmt_store_names(statement));
    });
    if let Some(function) = function {
        for parameter in function
            .parameters
            .posonlyargs
            .iter()
            .chain(&function.parameters.args)
            .chain(&function.parameters.kwonlyargs)
        {
            locals.insert(parameter.parameter.name.as_str().to_string());
        }
        if let Some(parameter) = function.parameters.vararg.as_deref() {
            locals.insert(parameter.name.as_str().to_string());
        }
        if let Some(parameter) = function.parameters.kwarg.as_deref() {
            locals.insert(parameter.name.as_str().to_string());
        }
    }
    for local in locals {
        child.values.insert(local, RandomIdentity::Unknown);
    }
    child
}

fn bind_statement(statement: &Stmt, bindings: &mut ScopeBindings) {
    match statement {
        Stmt::Import(import) => {
            for alias in &import.names {
                let local = alias.asname.as_deref().map_or_else(
                    || {
                        alias
                            .name
                            .as_str()
                            .split('.')
                            .next()
                            .unwrap_or("")
                            .to_owned()
                    },
                    str::to_string,
                );
                let identity = if alias.name.as_str() == "random" {
                    RandomIdentity::RandomModule
                } else {
                    RandomIdentity::Unknown
                };
                bindings.values.insert(local, identity);
            }
        }
        Stmt::ImportFrom(import) => {
            let module = import
                .module
                .as_ref()
                .map(ruff_python_ast::Identifier::as_str);
            for alias in &import.names {
                let local = alias
                    .asname
                    .as_deref()
                    .map_or_else(|| alias.name.as_str().to_string(), str::to_string);
                let identity = match (module, alias.name.as_str()) {
                    (Some("random"), "Random") => RandomIdentity::RandomClass,
                    (Some("random"), "SystemRandom") => RandomIdentity::SystemRandomClass,
                    (Some("random"), function) if PRNG_FUNCTIONS.contains(&function) => {
                        RandomIdentity::RandomFunction
                    }
                    _ => RandomIdentity::Unknown,
                };
                bindings.values.insert(local, identity);
            }
        }
        Stmt::Assign(assign) => {
            let identity = identity_of_expr(&assign.value, bindings);
            for target in &assign.targets {
                bind_target(target, identity, bindings);
            }
        }
        Stmt::AnnAssign(assign) => {
            let identity = assign
                .value
                .as_deref()
                .map_or(RandomIdentity::Unknown, |value| {
                    identity_of_expr(value, bindings)
                });
            bind_target(&assign.target, identity, bindings);
        }
        _ => {
            for name in stmt_store_names(statement) {
                bindings.values.insert(name, RandomIdentity::Unknown);
            }
        }
    }
}

fn bind_target(target: &Expr, identity: RandomIdentity, bindings: &mut ScopeBindings) {
    if let Expr::Name(name) = target {
        bindings
            .values
            .insert(name.id.as_str().to_string(), identity);
    } else {
        let mut names = Vec::new();
        crate::support::collect_target_names(target, &mut names);
        for name in names {
            bindings.values.insert(name, RandomIdentity::Unknown);
        }
    }
}

fn identity_of_expr(expr: &Expr, bindings: &ScopeBindings) -> RandomIdentity {
    match expr {
        Expr::Name(name) => bindings
            .values
            .get(name.id.as_str())
            .copied()
            .unwrap_or(RandomIdentity::Unknown),
        Expr::Attribute(attribute) => {
            let parent = identity_of_expr(&attribute.value, bindings);
            match (parent, attribute.attr.as_str()) {
                (RandomIdentity::RandomModule, "Random") => RandomIdentity::RandomClass,
                (RandomIdentity::RandomModule, "SystemRandom") => RandomIdentity::SystemRandomClass,
                _ => RandomIdentity::Unknown,
            }
        }
        Expr::Call(call) => match identity_of_expr(&call.func, bindings) {
            RandomIdentity::RandomClass => RandomIdentity::RandomInstance,
            RandomIdentity::SystemRandomClass => RandomIdentity::SystemRandomInstance,
            _ => RandomIdentity::Unknown,
        },
        _ => RandomIdentity::Unknown,
    }
}

fn is_unsafe_random_call(call: &ruff_python_ast::ExprCall, bindings: &ScopeBindings) -> bool {
    if matches!(
        identity_of_expr(&call.func, bindings),
        RandomIdentity::RandomFunction
    ) {
        return true;
    }
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return false;
    };
    if !PRNG_FUNCTIONS.contains(&attribute.attr.as_str()) {
        return false;
    }
    matches!(
        identity_of_expr(&attribute.value, bindings),
        RandomIdentity::RandomModule | RandomIdentity::RandomInstance
    )
}

fn is_security_context(name: &str) -> bool {
    name.to_lowercase()
        .split('_')
        .any(|word| SECURITY_CONTEXT_WORDS.contains(&word))
}

// --- python:S2245 — PRNGs in security contexts ---------------------------------

const SECURITY_CONTEXT_WORDS: [&str; 8] = [
    "token", "password", "secret", "key", "nonce", "salt", "cert", "auth",
];

const PRNG_FUNCTIONS: [&str; 10] = [
    "random",
    "getrandbits",
    "randint",
    "randrange",
    "choice",
    "choices",
    "uniform",
    "shuffle",
    "sample",
    "randbytes",
];

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s2245_flags_module_prng_calls() {
        let flagged = concat!(
            "import random\n",
            "\n",
            "random.getrandbits(1)\n",
            "random.randint(0, 9)\n",
            "random.random()\n",
            "random.choice([\"a\", \"b\"])\n"
        );
        let report = scan(flagged);
        let found = findings(&report, "python:S2245");
        assert_eq!(found.len(), 4);
        assert!(found.iter().all(|issue| issue.message
            == "Make sure that using this pseudorandom number generator is safe here."));
    }

    #[test]
    fn s2245_preserves_secure_and_system_random_sources() {
        let clean = concat!(
            "import random\n",
            "import secrets\n",
            "\n",
            "secrets.randbits(1)\n",
            "secrets.randbelow(10)\n",
            "secrets.token_hex(16)\n",
            "random.SystemRandom().choice([\"a\", \"b\"])\n",
            "rng = random.SystemRandom()\n",
            "choice = rng.choice((\"red\", \"blue\"))\n"
        );
        assert!(findings(&scan(clean), "python:S2245").is_empty());
    }

    #[test]
    fn s2245_preserves_rebound_and_sibling_local_bindings() {
        let source = concat!(
            "import random\n",
            "random = object()\n",
            "random.randint(1)\n",
            "\n",
            "def make_token():\n",
            "    return random.randint(0, 9)\n",
            "\n",
            "def stats():\n",
            "    return random.choice((\"red\", \"blue\"))\n"
        );
        assert!(findings(&scan(source), "python:S2245").is_empty());
        let secure = concat!(
            "import random\n",
            "\n",
            "def make_token():\n",
            "    return random.Random().randint(0, 9)\n"
        );
        assert_eq!(findings(&scan(secure), "python:S2245").len(), 1);
    }

    #[test]
    fn s2245_preserves_unimported_local_lookalikes_and_supports_aliases() {
        let local = "def randint(value):\n    return value\nrandint(1)\n";
        assert!(findings(&scan(local), "python:S2245").is_empty());
        let alias = "from random import getrandbits as bits\nbits(8)\n";
        assert_eq!(findings(&scan(alias), "python:S2245").len(), 1);
    }
}
