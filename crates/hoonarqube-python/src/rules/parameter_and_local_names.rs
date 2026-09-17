use crate::support::binding_target_names;
use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::for_each_function_def;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::function_all_parameters;
use crate::support::is_constant_name;
use crate::support::issue_at;
use crate::support::matches_snake_case;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtClassDef;
use ruff_python_ast::StmtFunctionDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use std::collections::HashSet;

/// Machine-learning convention names the reference check whitelists
/// (python:S117).
const ML_VARIABLE_NAMES: [&str; 6] = ["X_train", "X_test", "Y_train", "Y_test", "X", "Y"];

/// Parameters and locals of every function are python:S117; nested
/// definitions form their own scopes and are checked separately.
///
/// Mirroring the reference `LocalVariableAndParameterNameConventionCheck`:
/// all-caps constant names and variables assigned a type value are exempt on
/// assignment targets, single-character loop targets are exempt, and
/// parameters that reuse an overridden in-file method's parameter name are
/// exempt.
pub(crate) fn check_parameter_and_local_names(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut classes = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            classes.push(class);
        }
    });
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, _| {
            let mut seen = HashSet::new();
            let owner = owner_class(&classes, function.name.range());
            for (position, name) in function_all_parameters(function).into_iter().enumerate() {
                if !seen.insert(name.as_str().to_string()) {
                    continue;
                }
                if matches_snake_case(name.as_str())
                    || ML_VARIABLE_NAMES.contains(&name.as_str())
                    || parameter_is_type_like(function, name.as_str())
                    || parameter_matches_overridden(
                        &classes,
                        owner,
                        function,
                        name.as_str(),
                        position,
                    )
                {
                    continue;
                }
                issues.push(issue_at(
                    "python:S117",
                    &format!(
                        "Rename this parameter \"{name}\" to match the regular expression \
                         ^[_a-z][a-z0-9_]*$."
                    ),
                    name.range(),
                    index,
                    source,
                ));
            }
            for_each_stmt_in_scope(&function.body, &mut |stmt| {
                check_binding_statement(stmt, &classes, &mut seen, &mut issues, index, source);
                if let Stmt::Try(try_stmt) = stmt {
                    for handler in &try_stmt.handlers {
                        let ExceptHandler::ExceptHandler(inner) = handler;
                        if let Some(name) = &inner.name {
                            push_local_name_issue(
                                &mut issues,
                                &mut seen,
                                name.as_str(),
                                name.range(),
                                LocalKind::Assignment,
                                index,
                                source,
                            );
                        }
                    }
                }
            });
        },
    );
    issues
}

/// How a local name was bound; the reference exempts constants and
/// type-valued assignments only for assignment targets, and names of one
/// character only for loop declarations.
#[derive(Clone, Copy)]
enum LocalKind {
    Assignment,
    LoopTarget,
}

fn check_binding_statement(
    stmt: &Stmt,
    classes: &[&StmtClassDef],
    seen: &mut HashSet<String>,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let (targets, kind, assigned_value) = match stmt {
        Stmt::Assign(assign) => (
            assign
                .targets
                .iter()
                .flat_map(binding_target_names)
                .collect::<Vec<_>>(),
            LocalKind::Assignment,
            Some(assign.value.as_ref()),
        ),
        Stmt::AnnAssign(assignment) => (
            binding_target_names(&assignment.target),
            LocalKind::Assignment,
            assignment.value.as_deref(),
        ),
        Stmt::AugAssign(assignment) => (
            binding_target_names(&assignment.target),
            LocalKind::Assignment,
            None,
        ),
        Stmt::For(loop_stmt) => (
            binding_target_names(&loop_stmt.target),
            LocalKind::LoopTarget,
            None,
        ),
        Stmt::With(with_stmt) => (
            with_stmt
                .items
                .iter()
                .filter_map(|item| item.optional_vars.as_deref())
                .flat_map(binding_target_names)
                .collect(),
            LocalKind::Assignment,
            None,
        ),
        _ => return,
    };
    let type_assigned = assigned_value.is_some_and(|value| is_type_assignment(value, classes));
    for target in targets {
        if let Expr::Name(name) = target {
            let exempt = match kind {
                LocalKind::Assignment => is_constant_name(name.id.as_str()) || type_assigned,
                LocalKind::LoopTarget => name.id.len() <= 1,
            };
            if exempt {
                seen.insert(name.id.as_str().to_string());
            } else {
                push_local_name_issue(
                    issues,
                    seen,
                    name.id.as_str(),
                    target.range(),
                    kind,
                    index,
                    source,
                );
            }
        }
    }
}

fn push_local_name_issue(
    issues: &mut Vec<Issue>,
    seen: &mut HashSet<String>,
    name: &str,
    range: TextRange,
    _kind: LocalKind,
    index: &LineIndex,
    source: &str,
) {
    if !seen.insert(name.to_string())
        || matches_snake_case(name)
        || ML_VARIABLE_NAMES.contains(&name)
    {
        return;
    }
    issues.push(issue_at(
        "python:S117",
        "Rename this local variable to match the regular expression '^[_a-z][a-z0-9_]*$'.",
        range,
        index,
        source,
    ));
}

/// Whether the assigned value denotes a type rather than an instance:
/// `type(...)`/`TypeVar`/`NewType`/`namedtuple` calls, `Type[...]`-style
/// typing subscripts, references to classes defined in this file, and
/// `PascalCase` name or attribute references (imported classes).
fn is_type_assignment(value: &Expr, classes: &[&StmtClassDef]) -> bool {
    match value {
        Expr::Call(call) => {
            let callee = called_name(&call.func);
            let path = dotted_name(&call.func);
            matches!(
                callee,
                Some(
                    "type"
                        | "TypeVar"
                        | "NewType"
                        | "namedtuple"
                        | "NamedTuple"
                        | "Enum"
                        | "IntEnum"
                        | "Flag"
                        | "IntFlag"
                )
            ) || matches!(
                path.as_deref(),
                Some(
                    "typing.TypeVar"
                        | "typing.NewType"
                        | "collections.namedtuple"
                        | "typing.NamedTuple"
                        | "enum.Enum"
                        | "enum.IntEnum"
                        | "enum.Flag"
                        | "enum.IntFlag"
                )
            )
        }
        Expr::Subscript(subscript) => dotted_name(&subscript.value).is_some_and(|root| {
            matches!(
                root.as_str(),
                "type" | "Type" | "typing.Type" | "typing.TypeVar"
            )
        }),
        Expr::Name(name) => {
            name.id
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
                || classes
                    .iter()
                    .any(|class| class.name.as_str() == name.id.as_str())
        }
        Expr::Attribute(attribute) => attribute
            .attr
            .as_str()
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase()),
        _ => false,
    }
}

/// A parameter counts as type-like when its annotation names `type`/`Type`
/// or a `typing.*` form, or its default is a type-valued expression.
fn parameter_is_type_like(function: &StmtFunctionDef, name: &str) -> bool {
    let parameters = &function.parameters;
    let entries = parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs);
    for entry in entries {
        if entry.parameter.name.as_str() != name {
            continue;
        }
        if let Some(annotation) = entry.parameter.annotation.as_deref()
            && annotation_is_type(annotation)
        {
            return true;
        }
        if let Some(default) = entry.default.as_deref()
            && is_type_assignment(default, &[])
        {
            return true;
        }
    }
    false
}

fn annotation_is_type(annotation: &Expr) -> bool {
    match annotation {
        Expr::Subscript(subscript) => annotation_is_type(&subscript.value),
        Expr::Name(name) => matches!(name.id.as_str(), "type" | "Type" | "TypeVar"),
        Expr::Attribute(attribute) => {
            dotted_name(annotation)
                .is_some_and(|path| path.starts_with("typing.") || path == "builtins.type")
                || matches!(attribute.attr.as_str(), "Type" | "TypeVar")
        }
        _ => false,
    }
}

fn owner_class<'a>(
    classes: &[&'a StmtClassDef],
    name_range: TextRange,
) -> Option<&'a StmtClassDef> {
    classes.iter().copied().find(|class| {
        class.body.iter().any(
            |stmt| matches!(stmt, Stmt::FunctionDef(function) if function.name.range() == name_range),
        )
    })
}

/// The reference's isParameterNameFromOverriddenMethod reduced to in-file
/// facts: a positional parameter keeps the name of the same-index parameter
/// of a same-named method declared on an in-file base of the owner class.
fn parameter_matches_overridden(
    classes: &[&StmtClassDef],
    owner: Option<&StmtClassDef>,
    function: &StmtFunctionDef,
    name: &str,
    position: usize,
) -> bool {
    let Some(owner) = owner else {
        return false;
    };
    let mut pending: Vec<&StmtClassDef> = Vec::new();
    let mut visited: HashSet<&str> = HashSet::new();
    collect_in_file_bases(classes, owner, &mut pending);
    while let Some(base) = pending.pop() {
        if !visited.insert(base.name.as_str()) {
            continue;
        }
        if let Some(overridden) = base.body.iter().find_map(|stmt| {
            if let Stmt::FunctionDef(candidate) = stmt
                && candidate.name.as_str() == function.name.as_str()
            {
                Some(candidate)
            } else {
                None
            }
        }) {
            let overridden_names: Vec<&str> = positional_parameters(&overridden.parameters)
                .iter()
                .map(|parameter| parameter.name.as_str())
                .collect();
            if overridden_names
                .get(position)
                .is_some_and(|other| *other == name)
            {
                return true;
            }
        }
        collect_in_file_bases(classes, base, &mut pending);
    }
    false
}

fn collect_in_file_bases<'a>(
    classes: &[&'a StmtClassDef],
    class: &'a StmtClassDef,
    out: &mut Vec<&'a StmtClassDef>,
) {
    let Some(arguments) = class.arguments.as_deref() else {
        return;
    };
    for base in &arguments.args {
        if let Expr::Name(name) = base
            && let Some(found) = classes
                .iter()
                .copied()
                .find(|candidate| candidate.name.as_str() == name.id.as_str())
        {
            out.push(found);
        }
    }
}
