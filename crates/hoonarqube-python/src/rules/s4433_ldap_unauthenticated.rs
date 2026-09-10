use crate::engine::file_context::FileContext;
use crate::support::{
    child_bodies, for_each_expr, for_each_stmt_in_scope, issue_at, stmt_exprs, stmt_store_names,
    string_literal_text,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};

pub(crate) fn check_s4433_ldap_unauthenticated(
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
    LdapModule,
    LdapInitialize,
    LdapConnection,
    BoundConnection,
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
                process_call(call, bindings, index, source, issues);
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

fn process_call(
    call: &ruff_python_ast::ExprCall,
    bindings: &mut ScopeBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Some((receiver, method)) = ldap_method_receiver(call, bindings) else {
        return;
    };
    if LDAP_BIND_METHODS.contains(&method) {
        if unauthenticated_bind(call) {
            issues.push(issue_at(
                "python:S4433",
                "Provide a password when authenticating to this LDAP server.",
                call.func.range(),
                index,
                source,
            ));
        }
        bindings
            .values
            .insert(receiver, ValueState::BoundConnection);
    } else if LDAP_SEARCH_METHODS.contains(&method)
        && bindings.values.get(&receiver) != Some(&ValueState::BoundConnection)
    {
        issues.push(issue_at(
            "python:S4433",
            "Bind this LDAP connection with credentials before searching.",
            call.range(),
            index,
            source,
        ));
    }
}

fn ldap_method_receiver<'a>(
    call: &'a ruff_python_ast::ExprCall,
    bindings: &ScopeBindings,
) -> Option<(String, &'a str)> {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return None;
    };
    let Expr::Name(receiver) = attribute.value.as_ref() else {
        return None;
    };
    let state = bindings
        .values
        .get(receiver.id.as_str())
        .copied()
        .unwrap_or_else(|| {
            if receiver.id.as_str() == "ldap" {
                ValueState::LdapModule
            } else {
                ValueState::Unknown
            }
        });
    matches!(
        state,
        ValueState::LdapConnection | ValueState::BoundConnection
    )
    .then_some((receiver.id.as_str().to_string(), attribute.attr.as_str()))
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
                let state = if alias.name.as_str() == "ldap" {
                    ValueState::LdapModule
                } else {
                    ValueState::Unknown
                };
                bindings.values.insert(local, state);
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
                let state = if module == Some("ldap") && alias.name.as_str() == "initialize" {
                    ValueState::LdapInitialize
                } else {
                    ValueState::Unknown
                };
                bindings.values.insert(local, state);
            }
        }
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
    let Expr::Call(call) = value else {
        return ValueState::Unknown;
    };
    match call.func.as_ref() {
        Expr::Name(name)
            if bindings.values.get(name.id.as_str()) == Some(&ValueState::LdapInitialize) =>
        {
            ValueState::LdapConnection
        }
        Expr::Attribute(attribute)
            if attribute.attr.as_str() == "initialize"
                && identity_of_expr(attribute.value.as_ref(), bindings)
                    == ValueState::LdapModule =>
        {
            ValueState::LdapConnection
        }
        _ => ValueState::Unknown,
    }
}

fn identity_of_expr(expr: &Expr, bindings: &ScopeBindings) -> ValueState {
    match expr {
        Expr::Name(name) => bindings
            .values
            .get(name.id.as_str())
            .copied()
            .unwrap_or_else(|| {
                if name.id.as_str() == "ldap" {
                    ValueState::LdapModule
                } else {
                    ValueState::Unknown
                }
            }),
        _ => ValueState::Unknown,
    }
}

fn unauthenticated_bind(call: &ruff_python_ast::ExprCall) -> bool {
    let password = call.arguments.args.get(1).or_else(|| {
        call.arguments.keywords.iter().find_map(|keyword| {
            let argument = keyword.arg.as_ref()?;
            LDAP_PASSWORD_ARGUMENTS
                .contains(&argument.as_str())
                .then_some(&keyword.value)
        })
    });
    match password {
        None => true,
        Some(password) => {
            matches!(password, Expr::NoneLiteral(_))
                || string_literal_text(password).is_some_and(|text| text.is_empty())
        }
    }
}
// --- python:S4433 — LDAP connections should be authenticated -------------------

const LDAP_BIND_METHODS: [&str; 4] = ["simple_bind", "simple_bind_s", "bind", "bind_s"];
const LDAP_PASSWORD_ARGUMENTS: [&str; 3] = ["cred", "password", "passwd"];
const LDAP_SEARCH_METHODS: [&str; 3] = ["search_s", "search_ext_s", "search_st"];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s4433_flags_missing_or_none_bind_passwords() {
        let source = concat!(
            "import ldap\n",
            "\n",
            "def init_ldap():\n",
            "    connect = ldap.initialize(\"ldap://example:1389\")\n",
            "    connect.simple_bind(\"cn=root\")\n",
            "    connect.simple_bind_s(\"cn=root\")\n",
            "    connect.bind_s(\"cn=root\", None)\n",
            "    connect.bind(\"cn=root\", None)\n",
            "    return connect.search_s(base_dn, ldap.SCOPE_SUBTREE)\n"
        );
        let report = scan(source);
        let found = findings(&report, "python:S4433");
        assert_eq!(found.len(), 4);
        assert!(
            found.iter().all(|issue| issue.message
                == "Provide a password when authenticating to this LDAP server.")
        );
        assert_eq!(
            found
                .iter()
                .map(|issue| (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.line,
                    issue.range.end.column
                ))
                .collect::<Vec<_>>(),
            vec![(5, 4, 5, 23), (6, 4, 6, 25), (7, 4, 7, 18), (8, 4, 8, 16)]
        );

        let empty_password_report = scan(
            "import ldap\nconnection = ldap.initialize('ldap://example:1389')\nconnection.simple_bind('cn=root', '')\n",
        );
        let empty_password = findings(&empty_password_report, "python:S4433");
        assert_eq!(empty_password.len(), 1);
        assert_eq!(
            empty_password[0].message,
            "Provide a password when authenticating to this LDAP server."
        );
    }

    #[test]
    fn s4433_preserves_explicit_credentials_and_ldap_helper_aliases() {
        let safe = concat!(
            "import ldap as directory\n",
            "import os\n",
            "\n",
            "def lookup(server_url, base_dn):\n",
            "    connection = directory.initialize(server_url)\n",
            "    password = os.environ.get(\"LDAP_PASSWORD\")\n",
            "    connection.simple_bind(\"cn=reader\", password)\n",
            "    connection.simple_bind_s(\"cn=reader\", password)\n",
            "    connection.bind_s(\"cn=reader\", password)\n",
            "    connection.bind(\"cn=reader\", password)\n",
            "    return connection.search_s(base_dn, directory.SCOPE_SUBTREE)\n"
        );
        assert!(findings(&scan(safe), "python:S4433").is_empty());
    }

    #[test]
    fn s4433_flags_unbound_ldap_searches() {
        let search_report = scan("con = ldap.initialize(url)\ncon.search_s(base, scope)\n");
        let found = findings(&search_report, "python:S4433");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Bind this LDAP connection with credentials before searching."
        );
    }

    #[test]
    fn s4433_tracks_each_connection_and_rebound_ldap_names() {
        let source = concat!(
            "import ldap\n",
            "first = ldap.initialize(url)\n",
            "second = ldap.initialize(url)\n",
            "first.bind(\"cn=reader\", password)\n",
            "second.search_s(base, scope)\n"
        );
        let report = scan(source);
        let found = findings(&report, "python:S4433");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Bind this LDAP connection with credentials before searching."
        );
        let rebound = concat!(
            "import ldap\n",
            "ldap = object()\n",
            "connection = ldap.initialize(url)\n",
            "connection.bind(\"cn=root\")\n"
        );
        assert!(findings(&scan(rebound), "python:S4433").is_empty());
    }
}
