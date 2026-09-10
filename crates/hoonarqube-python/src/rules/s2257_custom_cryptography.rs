use crate::engine::file_context::FileContext;
use crate::support::{
    child_bodies, collect_target_names, for_each_stmt_expr, for_each_stmt_in_scope, issue_at,
    stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};

pub(crate) fn check_s2257_custom_cryptography(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut module_bindings = ScopeBindings::default();
    visit_scope(
        file_ctx.module_body,
        &mut module_bindings,
        index,
        source,
        &mut issues,
    );
    for function in &file_ctx.functions {
        let crypto_named = function
            .name
            .as_str()
            .to_lowercase()
            .split('_')
            .any(|word| {
                CUSTOM_CRYPTO_NAME_WORDS
                    .iter()
                    .any(|candidate| word.contains(candidate))
            });
        if crypto_named && contains_bitwise_xor(function.body.as_slice()) {
            issues.push(issue_at(
                "python:S2257",
                MESSAGE,
                function.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HasherIdentity {
    Unknown,
    Django,
    DjangoContrib,
    DjangoAuth,
    DjangoHashers,
    BasePasswordHasher,
}

#[derive(Clone, Default)]
struct ScopeBindings {
    values: HashMap<String, HasherIdentity>,
}

fn visit_scope(
    suite: &[Stmt],
    bindings: &mut ScopeBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for statement in suite {
        match statement {
            Stmt::ClassDef(class) => {
                for base in class.bases() {
                    if identity_of_expr(base, bindings) == HasherIdentity::BasePasswordHasher {
                        issues.push(issue_at(
                            "python:S2257",
                            MESSAGE,
                            base.range(),
                            index,
                            source,
                        ));
                    }
                }
                let mut child = child_scope(bindings, &class.body, None);
                visit_scope(&class.body, &mut child, index, source, issues);
            }
            Stmt::FunctionDef(function) => {
                let mut child = child_scope(bindings, &function.body, Some(function));
                visit_scope(&function.body, &mut child, index, source, issues);
            }
            _ => {
                for body in child_bodies(statement) {
                    visit_scope(body, bindings, index, source, issues);
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
        child.values.insert(local, HasherIdentity::Unknown);
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
                            .to_string()
                    },
                    str::to_string,
                );
                let identity = match alias.name.as_str() {
                    "django" => HasherIdentity::Django,
                    "django.contrib" => HasherIdentity::DjangoContrib,
                    "django.contrib.auth" => HasherIdentity::DjangoAuth,
                    "django.contrib.auth.hashers" => HasherIdentity::DjangoHashers,
                    _ => HasherIdentity::Unknown,
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
                    (Some("django"), "contrib") => HasherIdentity::DjangoContrib,
                    (Some("django.contrib"), "auth") => HasherIdentity::DjangoAuth,
                    (Some("django.contrib.auth"), "hashers") => HasherIdentity::DjangoHashers,
                    (Some("django.contrib.auth.hashers"), "BasePasswordHasher") => {
                        HasherIdentity::BasePasswordHasher
                    }
                    _ => HasherIdentity::Unknown,
                };
                bindings.values.insert(local, identity);
            }
        }
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                bind_target(target, HasherIdentity::Unknown, bindings);
            }
        }
        Stmt::AnnAssign(assign) => {
            bind_target(&assign.target, HasherIdentity::Unknown, bindings);
        }
        _ => {
            for name in stmt_store_names(statement) {
                bindings.values.insert(name, HasherIdentity::Unknown);
            }
        }
    }
}

fn bind_target(target: &Expr, identity: HasherIdentity, bindings: &mut ScopeBindings) {
    if let Expr::Name(name) = target {
        bindings
            .values
            .insert(name.id.as_str().to_string(), identity);
        return;
    }
    let mut names = Vec::new();
    collect_target_names(target, &mut names);
    for name in names {
        bindings.values.insert(name, identity);
    }
}

fn identity_of_expr(expr: &Expr, bindings: &ScopeBindings) -> HasherIdentity {
    match expr {
        Expr::Name(name) => bindings
            .values
            .get(name.id.as_str())
            .copied()
            .unwrap_or(HasherIdentity::Unknown),
        Expr::Attribute(attribute) => {
            let parent = identity_of_expr(attribute.value.as_ref(), bindings);
            match (parent, attribute.attr.as_str()) {
                (HasherIdentity::Django, "contrib") => HasherIdentity::DjangoContrib,
                (HasherIdentity::DjangoContrib, "auth") => HasherIdentity::DjangoAuth,
                (HasherIdentity::DjangoAuth, "hashers") => HasherIdentity::DjangoHashers,
                (HasherIdentity::DjangoHashers, "BasePasswordHasher") => {
                    HasherIdentity::BasePasswordHasher
                }
                _ => HasherIdentity::Unknown,
            }
        }
        _ => HasherIdentity::Unknown,
    }
}

fn contains_bitwise_xor(suite: &[Stmt]) -> bool {
    let mut found = false;
    for_each_stmt_expr(suite, &mut |expr| {
        if let Expr::BinOp(binop) = expr
            && matches!(binop.op, ruff_python_ast::Operator::BitXor)
        {
            found = true;
        }
    });
    found
}

// --- python:S2257 — custom cryptographic algorithms -----------------------------

const MESSAGE: &str = "Make sure using a non-standard cryptographic algorithm is safe here.";
const CUSTOM_CRYPTO_NAME_WORDS: [&str; 7] =
    ["encrypt", "decrypt", "cipher", "xor", "crypt", "rc4", "des"];

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s2257_flags_django_base_password_hasher_subclasses() {
        let flagged = concat!(
            "from django.contrib.auth.hashers import BasePasswordHasher\n",
            "\n",
            "class CustomPasswordHasher(BasePasswordHasher):\n",
            "    pass\n"
        );
        let report = scan(flagged);
        let found = findings(&report, "python:S2257");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Make sure using a non-standard cryptographic algorithm is safe here."
        );
        assert_eq!(
            (
                found[0].range.start.line,
                found[0].range.start.column,
                found[0].range.end.line,
                found[0].range.end.column
            ),
            (3, 27, 3, 45)
        );
    }

    #[test]
    fn s2257_preserves_reviewed_and_local_same_named_hashers() {
        let safe = concat!(
            "from django.contrib.auth.hashers import Argon2PasswordHasher\n",
            "\n",
            "hasher = Argon2PasswordHasher()\n"
        );
        assert!(findings(&scan(safe), "python:S2257").is_empty());
        let local = "class CustomPasswordHasher(object):\n    pass\n";
        assert!(findings(&scan(local), "python:S2257").is_empty());
    }
    #[test]
    fn s2257_supports_qualified_hasher_aliases_and_rebinding() {
        let aliased = concat!(
            "import django.contrib.auth as auth\n",
            "\n",
            "class CustomPasswordHasher(auth.hashers.BasePasswordHasher):\n",
            "    pass\n"
        );
        assert_eq!(findings(&scan(aliased), "python:S2257").len(), 1);
        let rebound = concat!(
            "from django.contrib.auth.hashers import BasePasswordHasher\n",
            "BasePasswordHasher = object\n",
            "\n",
            "class LocalHasher(BasePasswordHasher):\n",
            "    pass\n"
        );
        assert!(findings(&scan(rebound), "python:S2257").is_empty());
    }

    #[test]
    fn s2257_retains_hand_rolled_cipher_function_detection() {
        let flagged = concat!(
            "def xor_encrypt(data, key):\n",
            "    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2257").len(), 1);
        let clean = "def hash_password(pw):\n    return sha256(pw).hexdigest()\n";
        assert!(findings(&scan(clean), "python:S2257").is_empty());
    }
}
