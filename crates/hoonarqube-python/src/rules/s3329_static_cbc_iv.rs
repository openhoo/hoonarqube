use crate::engine::file_context::FileContext;
use crate::support::{
    child_bodies, for_each_expr, for_each_stmt_in_scope, is_call_method, is_static_text_literal,
    issue_at, keyword_value, stmt_exprs, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::{HashMap, HashSet};

// --- python:S3329 — unpredictable CBC IVs --------------------------------------

pub(crate) fn check_s3329_static_cbc_iv(
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
    issues
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueState {
    Unknown,
    StaticText,
    StaticCipher,
}

#[derive(Clone, Default)]
struct ScopeBindings {
    values: HashMap<String, ValueState>,
}

fn visit_scope(
    suite: &[Stmt],
    bindings: &mut ScopeBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for statement in suite {
        for expression in stmt_exprs(statement) {
            for_each_expr(expression, &mut |expression| {
                let Expr::Call(call) = expression else {
                    return;
                };
                let Some(receiver) = encryption_receiver(call) else {
                    return;
                };
                let Expr::Attribute(attribute) = call.func.as_ref() else {
                    return;
                };
                let Expr::Name(name) = attribute.value.as_ref() else {
                    return;
                };
                if bindings.values.get(name.id.as_str()) == Some(&ValueState::StaticCipher) {
                    issues.push(issue_at(
                        "python:S3329",
                        "Use a dynamically-generated, random IV.",
                        receiver,
                        index,
                        source,
                    ));
                }
            });
        }

        match statement {
            Stmt::FunctionDef(function) => {
                let mut child = child_scope(bindings, &function.body, Some(function));
                visit_scope(&function.body, &mut child, index, source, issues);
            }
            Stmt::ClassDef(class) => {
                let mut child = child_scope(bindings, &class.body, None);
                visit_scope(&class.body, &mut child, index, source, issues);
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
        child.values.insert(local, ValueState::Unknown);
    }
    child
}

fn bind_statement(statement: &Stmt, bindings: &mut ScopeBindings) {
    match statement {
        Stmt::Assign(assign) => {
            let state = assignment_state(&assign.value, bindings);
            for target in &assign.targets {
                bind_target(target, state, bindings);
            }
        }
        Stmt::AnnAssign(assign) => {
            let state = assign
                .value
                .as_deref()
                .map_or(ValueState::Unknown, |value| {
                    assignment_state(value, bindings)
                });
            bind_target(&assign.target, state, bindings);
        }
        _ => {
            for name in stmt_store_names(statement) {
                bindings.values.insert(name, ValueState::Unknown);
            }
        }
    }
}

fn bind_target(target: &Expr, state: ValueState, bindings: &mut ScopeBindings) {
    if let Expr::Name(name) = target {
        bindings.values.insert(name.id.as_str().to_string(), state);
        return;
    }
    let mut names = Vec::new();
    crate::support::collect_target_names(target, &mut names);
    for name in names {
        bindings.values.insert(name, ValueState::Unknown);
    }
}

fn assignment_state(value: &Expr, bindings: &ScopeBindings) -> ValueState {
    if is_static_text_literal(value) {
        return ValueState::StaticText;
    }
    let Expr::Call(call) = value else {
        return ValueState::Unknown;
    };
    cipher_constructor_state(call, bindings).map_or(ValueState::Unknown, |static_iv| {
        if static_iv {
            ValueState::StaticCipher
        } else {
            ValueState::Unknown
        }
    })
}

fn cipher_constructor_state(
    call: &ruff_python_ast::ExprCall,
    bindings: &ScopeBindings,
) -> Option<bool> {
    const BLOCK_CIPHERS: [&str; 5] = ["AES", "DES", "DES3", "ARC2", "Blowfish"];
    let block_cipher_new = is_call_method(call, "new")
        && crate::support::dotted_name_parent_in(&call.func, &BLOCK_CIPHERS);
    if block_cipher_new {
        let mode = keyword_value(&call.arguments, "mode").or_else(|| call.arguments.args.get(1));
        if !mode.is_some_and(is_cbc_mode) {
            return None;
        }
        let iv = keyword_value(&call.arguments, "iv").or_else(|| call.arguments.args.get(2));
        return Some(iv.is_some_and(|value| is_static_iv(value, bindings)));
    }
    if is_call_method(call, "Cipher") {
        let cbc = call
            .arguments
            .args
            .iter()
            .find_map(|argument| match argument {
                Expr::Call(nested) if is_call_method(nested, "CBC") => Some(nested),
                _ => None,
            })?;
        return Some(
            cbc.arguments
                .args
                .first()
                .is_some_and(|value| is_static_iv(value, bindings)),
        );
    }
    None
}

fn is_cbc_mode(expr: &Expr) -> bool {
    crate::support::dotted_name(expr).is_some_and(|path| path.ends_with(".MODE_CBC"))
}

fn is_static_iv(expr: &Expr, bindings: &ScopeBindings) -> bool {
    is_static_text_literal(expr)
        || matches!(
            expr,
            Expr::Name(name)
                if bindings.values.get(name.id.as_str()) == Some(&ValueState::StaticText)
        )
}

fn encryption_receiver(call: &ruff_python_ast::ExprCall) -> Option<TextRange> {
    const ENCRYPTION_METHODS: [&str; 3] = ["encrypt", "encryptor", "encrypt_and_digest"];
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return None;
    };
    ENCRYPTION_METHODS
        .contains(&attribute.attr.as_str())
        .then(|| attribute.value.range())
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3329_flags_name_bound_static_cbc_iv_at_encryption() {
        let flagged = concat!(
            "from Crypto.Cipher import AES\n",
            "\n",
            "iv = b\"exampleIV1234567\"\n",
            "cipher = AES.new(key, AES.MODE_CBC, iv)\n",
            "cipher.encrypt(data)\n"
        );
        let report = scan(flagged);
        let found = findings(&report, "python:S3329");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].message, "Use a dynamically-generated, random IV.");
        assert_eq!(
            (
                found[0].range.start.line,
                found[0].range.start.column,
                found[0].range.end.line,
                found[0].range.end.column
            ),
            (5, 0, 5, 6)
        );
    }

    #[test]
    fn s3329_preserves_random_and_provider_generated_ivs() {
        let safe = concat!(
            "from Crypto.Cipher import AES\n",
            "from Crypto.Random import get_random_bytes\n",
            "\n",
            "iv = get_random_bytes(AES.block_size)\n",
            "cipher = AES.new(key, AES.MODE_CBC, iv)\n",
            "cipher.encrypt(data)\n"
        );
        assert!(findings(&scan(safe), "python:S3329").is_empty());
        let near_miss = concat!(
            "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n",
            "\n",
            "def encrypt(data, key, iv_provider):\n",
            "    iv = iv_provider()\n",
            "    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))\n",
            "    return cipher.encryptor()\n"
        );
        assert!(findings(&scan(near_miss), "python:S3329").is_empty());
    }
    #[test]
    fn s3329_drops_static_cipher_state_after_rebinding() {
        let source = concat!(
            "from Crypto.Cipher import AES\n",
            "\n",
            "iv = b\"exampleIV1234567\"\n",
            "cipher = AES.new(key, AES.MODE_CBC, iv)\n",
            "cipher = object()\n",
            "cipher.encrypt(data)\n"
        );
        assert!(findings(&scan(source), "python:S3329").is_empty());
    }
}
