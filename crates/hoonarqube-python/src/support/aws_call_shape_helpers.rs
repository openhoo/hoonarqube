// --- AWS call-shape helpers

use crate::support::{
    WebFrameworkFacts, for_each_stmt_expr, for_each_stmt_expr_in_scope, string_literal_text,
};
use ruff_python_ast::{Expr, ExprCall, Stmt, StmtFunctionDef};
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashSet;

/// Source slice of a whole call expression (name-table text searches).
pub(crate) fn call_source_text<'a>(call: &ruff_python_ast::ExprCall, source: &'a str) -> &'a str {
    let range = call.range();
    source
        .get(range.start().to_usize()..range.end().to_usize())
        .unwrap_or_default()
}

pub(crate) fn for_each_dict_literal(
    stmts: &[Stmt],
    visit: &mut dyn FnMut(&ruff_python_ast::ExprDict),
) {
    for_each_stmt_expr(stmts, &mut |expr| {
        if let Expr::Dict(dict) = expr {
            visit(dict);
        }
    });
}

pub(crate) fn dict_string_entry<'a>(
    dict: &'a ruff_python_ast::ExprDict,
    key: &str,
) -> Option<&'a Expr> {
    dict.items.iter().find_map(|item| {
        item.key
            .as_ref()
            .and_then(string_literal_text)
            .filter(|text| text == key)
            .map(|_| &item.value)
    })
}

fn is_wildcard_string(expr: &Expr) -> bool {
    string_literal_text(expr).as_deref() == Some("*")
}

/// Whether the value is `"*"` or a mapping whose `"AWS"` entry is `"*"`.
pub(crate) fn grants_to_all_principals(expr: &Expr) -> bool {
    match expr {
        Expr::Dict(dict) => dict_string_entry(dict, "AWS").is_some_and(is_wildcard_string),
        _ => is_wildcard_string(expr),
    }
}

// ---------------------------------------------------------------------------
// Shared boto3/CDK machinery for the python:S6243, python:S6246,
// python:S6249, python:S6262, and python:S7625 detectors.
//
// The reference checks lean on SonarPython's type system (`isTypeWithFqn`,
// `inferSingleAssignedExpressionType`, `Expressions.singleAssignedValue`).
// Hoonarqube reconstructs the same identities with `WebFrameworkFacts`:
// import aliases resolve to their module path, `name = Constructor(...)`
// bindings resolve through the scope chain, and attribute tails append.
// ---------------------------------------------------------------------------

/// Canonical AWS FQN of `expr`: collapses the doubled tail segment that
/// `import boto3.session` / `import mysql.connector` produce when the bound
/// root already names the submodule, and maps the `boto3.Session` re-export
/// onto `boto3.session.Session`.
pub(crate) fn aws_fqn(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> Option<String> {
    let fqn = facts.expr_fqn(expr)?;
    let mut segments: Vec<&str> = fqn.split('.').collect();
    segments.dedup();
    let collapsed = segments.join(".");
    if collapsed == "boto3.Session" || collapsed.starts_with("boto3.Session.") {
        return Some(collapsed.replacen("boto3.Session", "boto3.session.Session", 1));
    }
    Some(collapsed)
}

/// Boto3 call shapes the AWS rules dispatch on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Boto3Callee {
    /// `boto3.client(...)`
    Client,
    /// `boto3.resource(...)`
    Resource,
    /// `boto3.session.Session(...)` (any import spelling)
    SessionNew,
    /// `<session>.client(...)`
    SessionClient,
    /// `<session>.resource(...)`
    SessionResource,
}

/// Classifies `call.func` as a boto3 client/resource/session producer. A
/// `<name>.client` / `<name>.resource` receiver counts when every assignment
/// of `name` visible from the call site constructs a `boto3` `Session`.
pub(crate) fn boto3_callee(facts: &WebFrameworkFacts<'_>, call: &ExprCall) -> Option<Boto3Callee> {
    let at = call.range();
    if let Some(fqn) = aws_fqn(facts, &call.func) {
        return match fqn.as_str() {
            "boto3.client" => Some(Boto3Callee::Client),
            "boto3.resource" => Some(Boto3Callee::Resource),
            "boto3.session.Session" => Some(Boto3Callee::SessionNew),
            "boto3.session.Session.client" => Some(Boto3Callee::SessionClient),
            "boto3.session.Session.resource" => Some(Boto3Callee::SessionResource),
            _ => None,
        };
    }
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return None;
    };
    let Expr::Name(receiver) = attribute.value.as_ref() else {
        return None;
    };
    if !is_session_receiver(facts, receiver.id.as_str(), at) {
        return None;
    }
    match attribute.attr.as_str() {
        "client" => Some(Boto3Callee::SessionClient),
        "resource" => Some(Boto3Callee::SessionResource),
        _ => None,
    }
}

/// Whether `name` read at `at` is a boto3 `Session` object: either the
/// scope-resolved single assignment constructs one, or every plain
/// assignment of `name` in the scopes enclosing `at` does (the reference's
/// declared-type inference keeps the `Session` type across reassignments).
fn is_session_receiver(facts: &WebFrameworkFacts<'_>, name: &str, at: TextRange) -> bool {
    all_assigned_values_match(facts, name, at, &|value| {
        matches!(
            value,
            Expr::Call(call)
                if aws_fqn(facts, &call.func).as_deref() == Some("boto3.session.Session")
        )
    })
}

/// Whether `name` read at `at` is a boto3 client object: every plain
/// assignment in the scopes enclosing `at` calls `boto3.client` or
/// `<session>.client`.
pub(crate) fn is_client_receiver(facts: &WebFrameworkFacts<'_>, name: &str, at: TextRange) -> bool {
    all_assigned_values_match(facts, name, at, &|value| {
        matches!(
            value,
            Expr::Call(call)
                if matches!(
                    boto3_callee(facts, call),
                    Some(Boto3Callee::Client | Boto3Callee::SessionClient)
                )
        )
    })
}

/// Every plain `name = value` assignment visible from `at` must satisfy
/// `predicate`, and at least one must exist. Single assignments resolve
/// through the scope chain first so a same-scope binding wins over an
/// unrelated outer one.
fn all_assigned_values_match(
    facts: &WebFrameworkFacts<'_>,
    name: &str,
    at: TextRange,
    predicate: &dyn Fn(&Expr) -> bool,
) -> bool {
    if let Some(value) = facts.single_assigned_value(name, at) {
        return predicate(value);
    }
    let chain: HashSet<Option<TextRange>> = facts.enclosing_chain(at).into_iter().collect();
    let mut matched = false;
    let mut failed = false;
    for stmt in &facts.stmts {
        let stmt: &Stmt = stmt;
        let value: Option<&Expr> = match stmt {
            Stmt::Assign(assign)
                if assign.targets.iter().any(
                    |target| matches!(target, Expr::Name(target) if target.id.as_str() == name),
                ) =>
            {
                Some(assign.value.as_ref())
            }
            Stmt::AnnAssign(assign) if matches!(assign.target.as_ref(), Expr::Name(target) if target.id.as_str() == name) => {
                assign.value.as_deref()
            }
            _ => None,
        };
        if let Some(value) = value
            && chain.contains(&facts.enclosing_scope(stmt.range()))
        {
            matched = true;
            if !predicate(value) {
                failed = true;
            }
        }
    }
    matched && !failed
}

/// `Expressions.ifNameGetSingleAssignedNonNameValue`: a `Name` resolves to
/// its single assigned value when that value is not itself a `Name`;
/// anything else resolves to the expression unchanged.
pub(crate) fn resolved_value<'a>(facts: &WebFrameworkFacts<'a>, expr: &'a Expr) -> &'a Expr {
    if let Expr::Name(name) = expr
        && let Some(value) = facts.single_assigned_value(name.id.as_str(), name.range())
        && !matches!(value, Expr::Name(_))
    {
        return value;
    }
    expr
}

/// String text of `expr` after the single-assignment resolution the
/// reference checks apply to keyword arguments.
pub(crate) fn resolved_string_literal(
    facts: &WebFrameworkFacts<'_>,
    expr: &Expr,
) -> Option<String> {
    string_literal_text(resolved_value(facts, expr))
}

/// Positional argument `position` of `call`, else the `name` keyword's value
/// (`TreeUtils.nthArgumentOrKeyword`).
pub(crate) fn nth_or_keyword_arg<'a>(
    call: &'a ExprCall,
    position: usize,
    name: &str,
) -> Option<&'a Expr> {
    if let Some(expr) = call.arguments.args.get(position) {
        return Some(expr);
    }
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some(name))
        .map(|keyword| &keyword.value)
}

/// Range of positional argument `position`, else of the whole `name` keyword
/// (`name=value`), matching the reference's `RegularArgument` anchor.
pub(crate) fn nth_or_keyword_range(
    call: &ExprCall,
    position: usize,
    name: &str,
) -> Option<TextRange> {
    if let Some(expr) = call.arguments.args.get(position) {
        return Some(expr.range());
    }
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some(name))
        .map(Ranged::range)
}

/// Whether the call passes a `**mapping` whose value is not a literal dict
/// (the reference cannot see through it, so the rules skip the call).
pub(crate) fn has_unknown_keyword_unpack(arguments: &ruff_python_ast::Arguments) -> bool {
    arguments
        .keywords
        .iter()
        .any(|keyword| keyword.arg.is_none() && !matches!(keyword.value, Expr::Dict(_)))
}

/// `name` entry of a literal-dict `**{...}` unpack, if present.
pub(crate) fn literal_unpacked_keyword<'a>(
    arguments: &'a ruff_python_ast::Arguments,
    name: &str,
) -> Option<&'a Expr> {
    arguments.keywords.iter().find_map(|keyword| {
        if keyword.arg.is_some() {
            return None;
        }
        let Expr::Dict(dict) = &keyword.value else {
            return None;
        };
        dict_string_entry(dict, name)
    })
}

// ---------------------------------------------------------------------------
// Lambda-handler detection (`SignatureBasedAwsLambdaHandlersCollector` plus
// the call-graph walk of `AwsLambdaChecksUtils.isLambdaHandler`): a function
// counts as a handler when its name ends in `_handler`/`Handler` and it takes
// exactly `(event, context|ctx)`, or when a handler calls it.
// ---------------------------------------------------------------------------

fn has_handler_signature(function: &StmtFunctionDef) -> bool {
    let name = function.name.as_str();
    if !(name.ends_with("_handler") || name.ends_with("Handler")) {
        return false;
    }
    let parameters = &function.parameters;
    let names: Vec<&str> = parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .map(|parameter| parameter.parameter.name.as_str())
        .collect();
    names.len() == 2 && names[0] == "event" && matches!(names[1], "context" | "ctx")
}

/// Ranges of every function definition that acts as a Lambda handler:
/// signature handlers plus everything transitively called from one.
pub(crate) fn lambda_handler_ranges(facts: &WebFrameworkFacts<'_>) -> HashSet<TextRange> {
    let mut handlers: HashSet<TextRange> = facts
        .functions
        .iter()
        .filter(|function| has_handler_signature(function))
        .map(Ranged::range)
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for function in &facts.functions {
            if !handlers.contains(&function.range()) {
                continue;
            }
            for_each_stmt_expr_in_scope(&function.body, &mut |expr| {
                if let Expr::Call(call) = expr
                    && let Some(target) =
                        facts.resolve_function_def(call.func.as_ref(), call.range())
                    && handlers.insert(target.range())
                {
                    changed = true;
                }
            });
        }
    }
    handlers
}

/// Whether `at` sits inside a function that is a Lambda handler (the
/// reference checks the innermost enclosing `FUNCDEF` only).
pub(crate) fn in_lambda_handler(
    facts: &WebFrameworkFacts<'_>,
    handlers: &HashSet<TextRange>,
    at: TextRange,
) -> bool {
    facts
        .enclosing_chain(at)
        .into_iter()
        .find_map(|scope| scope)
        .is_some_and(|scope| handlers.contains(&scope))
}
