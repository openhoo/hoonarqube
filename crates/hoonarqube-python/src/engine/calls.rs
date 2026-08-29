use crate::support::child_bodies;
use crate::support::child_exprs;
use crate::support::collect_target_names;
use crate::support::direct_base_names;
use crate::support::expr_normalized_text;
use crate::support::has_decorator;
use crate::support::parameter_entries;
use crate::support::s5655_check_argument;
use crate::support::stmt_exprs;
use crate::support::stmt_store_names;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use std::collections::HashMap;
use std::collections::HashSet;

// --- shared: simple concrete annotation hints ---------------------------------

/// Builtin annotations whose literal compatibility is decodable from the root
/// name alone (`int`, `list[int]`, `typing.Dict[str, int]`). PEP 604 unions,
/// `Optional[...]`, `Any`, `object`, string forward references, and unknown
/// class names are deliberately unrecognized.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HintKind {
    Int,
    Float,
    Complex,
    Str,
    Bytes,
    Bool,
    List,
    Set,
    Dict,
    Tuple,
    FrozenSet,
}

pub(crate) fn concrete_hint(annotation: &Expr) -> Option<HintKind> {
    let root = match annotation {
        Expr::Name(name) => name.id.as_str(),
        Expr::Attribute(attribute) => attribute.attr.as_str(),
        Expr::Subscript(subscript) => match subscript.value.as_ref() {
            Expr::Name(name) => name.id.as_str(),
            Expr::Attribute(attribute) => attribute.attr.as_str(),
            _ => return None,
        },
        _ => return None,
    };
    Some(match root {
        "int" => HintKind::Int,
        "float" => HintKind::Float,
        "complex" => HintKind::Complex,
        "str" => HintKind::Str,
        "bytes" => HintKind::Bytes,
        "bool" => HintKind::Bool,
        "list" | "List" => HintKind::List,
        "set" | "Set" => HintKind::Set,
        "dict" | "Dict" => HintKind::Dict,
        "tuple" | "Tuple" => HintKind::Tuple,
        "frozenset" | "FrozenSet" => HintKind::FrozenSet,
        _ => return None,
    })
}

/// Whether a value of literal kind `kind` can populate a `hint` slot.
/// Booleans count as ints; ints widen to `float`/`complex`; a `frozenset`
/// slot accepts none of the mutable collection literals.
pub(crate) fn hint_accepts_literal(hint: HintKind, kind: &str) -> bool {
    match hint {
        HintKind::Int => matches!(kind, "int" | "boolean"),
        HintKind::Float | HintKind::Complex => {
            matches!(kind, "int" | "float" | "complex" | "boolean")
        }
        HintKind::Str => kind == "string",
        HintKind::Bytes => kind == "bytes",
        HintKind::Bool => kind == "boolean",
        HintKind::List => kind == "list",
        HintKind::Set => kind == "set",
        HintKind::Dict => kind == "dict",
        HintKind::Tuple => kind == "tuple",
        HintKind::FrozenSet => false,
    }
}

// --- shared: file-local call resolution ---------------------------------------

/// A callable resolvable entirely inside the analyzed file.
#[derive(Clone, Copy)]
pub(crate) enum ResolvedCallee<'a> {
    /// Plain module-level function call `f(...)`.
    Function(&'a ruff_python_ast::StmtFunctionDef),
    /// Bound form (`ClassName(...)`, `self.m`, instance or class access)
    /// where the receiver supplies the leading parameter unless the method
    /// is a `@staticmethod`.
    Bound(&'a ruff_python_ast::StmtFunctionDef, bool),
}

impl ResolvedCallee<'_> {
    fn function(&self) -> &ruff_python_ast::StmtFunctionDef {
        match self {
            ResolvedCallee::Function(function) | ResolvedCallee::Bound(function, _) => function,
        }
    }

    fn skips_receiver(self) -> bool {
        matches!(self, ResolvedCallee::Bound(_, false))
    }
}

/// File-local call-resolution tables shared by the S930/S5655 family:
/// module-level functions, file-local classes, and instance bindings of the
/// shape `v = ClassName(...)` written exactly once at module level.
pub(crate) struct LocalSignatures<'a> {
    functions: HashMap<String, &'a ruff_python_ast::StmtFunctionDef>,
    classes: HashMap<String, &'a ruff_python_ast::StmtClassDef>,
    instances: HashMap<String, String>,
}

impl<'a> LocalSignatures<'a> {
    /// Collects module-level definitions only; duplicate names are dropped as
    /// ambiguous, and instance bindings must come from a single unconflicted
    /// constructor assignment.
    pub(crate) fn new(module: &'a [Stmt]) -> Self {
        let writes = module_scope_write_counts(module);
        let (functions, classes) = collect_local_definitions(module, &writes);
        let instances = collect_instance_bindings(module, &classes, &writes);
        Self {
            functions,
            classes,
            instances,
        }
    }

    /// Nearest declaration of `method` walking the file-local base chain of
    /// `class_name`; cycles are cut by the visited set.
    fn nearest_method(&self, class_name: &str, method: &str) -> Option<ResolvedCallee<'a>> {
        let mut pending = vec![class_name.to_string()];
        let mut visited = HashSet::new();
        while let Some(class_name) = pending.pop() {
            if !visited.insert(class_name.clone()) {
                continue;
            }
            let Some(class) = self.classes.get(class_name.as_str()) else {
                continue;
            };
            for stmt in &class.body {
                if let Stmt::FunctionDef(function) = stmt
                    && function.name.as_str() == method
                {
                    return Some(ResolvedCallee::Bound(
                        function,
                        has_decorator(function, "staticmethod"),
                    ));
                }
            }
            pending.extend(
                direct_base_names(class)
                    .into_iter()
                    .rev()
                    .map(str::to_owned),
            );
        }
        None
    }

    /// Resolves a call's callee expression against the tables.
    pub(crate) fn resolve(
        &self,
        func: &Expr,
        class_context: Option<&str>,
    ) -> Option<ResolvedCallee<'a>> {
        match func {
            Expr::Name(callee) => {
                if let Some(function) = self.functions.get(callee.id.as_str()) {
                    return Some(ResolvedCallee::Function(function));
                }
                if self.classes.contains_key(callee.id.as_str()) {
                    return self.nearest_method(callee.id.as_str(), "__init__");
                }
                None
            }
            Expr::Attribute(attribute) => {
                let Expr::Name(owner) = attribute.value.as_ref() else {
                    return None;
                };
                let method = attribute.attr.as_str();
                match owner.id.as_str() {
                    "self" | "cls" => self.nearest_method(class_context?, method),
                    name => {
                        if let Some(class_name) = self.instances.get(name) {
                            return self.nearest_method(class_name, method);
                        }
                        if self.classes.contains_key(name) {
                            return self.nearest_method(name, method);
                        }
                        None
                    }
                }
            }
            _ => None,
        }
    }
}

fn collect_local_definitions<'a>(
    module: &'a [Stmt],
    writes: &HashMap<String, usize>,
) -> (
    HashMap<String, &'a ruff_python_ast::StmtFunctionDef>,
    HashMap<String, &'a ruff_python_ast::StmtClassDef>,
) {
    let mut functions: HashMap<String, &'a ruff_python_ast::StmtFunctionDef> = HashMap::new();
    let mut classes: HashMap<String, &'a ruff_python_ast::StmtClassDef> = HashMap::new();
    for stmt in module {
        match stmt {
            Stmt::FunctionDef(function) => {
                let name = function.name.as_str();
                if writes.get(name).copied() == Some(1) {
                    functions.insert(name.to_string(), function);
                }
            }
            Stmt::ClassDef(class) => {
                let name = class.name.as_str();
                if writes.get(name).copied() == Some(1) {
                    classes.insert(name.to_string(), class);
                }
            }
            _ => {}
        }
    }
    (functions, classes)
}

/// Counts every write performed in module scope without descending into
/// function or class bodies. This includes module-level control-flow bodies
/// and assignment expressions in statement headers.
fn module_scope_write_counts(module: &[Stmt]) -> HashMap<String, usize> {
    let mut writes = HashMap::new();
    let mut pending: Vec<&Stmt> = module.iter().rev().collect();
    while let Some(stmt) = pending.pop() {
        count_statement_writes(stmt, &mut writes);
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        for body in child_bodies(stmt).into_iter().rev() {
            pending.extend(body.iter().rev());
        }
    }
    writes
}

fn count_statement_writes(stmt: &Stmt, writes: &mut HashMap<String, usize>) {
    add_writes(writes, stmt_store_names(stmt));
    let mut expressions = stmt_exprs(stmt);
    while let Some(expr) = expressions.pop() {
        if let Expr::Named(named) = expr {
            let mut names = Vec::new();
            collect_target_names(&named.target, &mut names);
            add_writes(writes, names);
        }
        expressions.extend(child_exprs(expr));
    }
}

fn add_writes(writes: &mut HashMap<String, usize>, names: Vec<String>) {
    for name in names {
        *writes.entry(name).or_insert(0) += 1;
    }
}

fn collect_instance_bindings(
    module: &[Stmt],
    classes: &HashMap<String, &ruff_python_ast::StmtClassDef>,
    writes: &HashMap<String, usize>,
) -> HashMap<String, String> {
    let mut instances: HashMap<String, String> = HashMap::new();
    for stmt in module {
        if let Stmt::Assign(assign) = stmt
            && let [target] = assign.targets.as_slice()
            && let Expr::Name(name) = target
            && let Expr::Call(call) = assign.value.as_ref()
            && let Expr::Name(callee) = call.func.as_ref()
            && classes.contains_key(callee.id.as_str())
        {
            let key = name.id.as_str();
            instances
                .entry(key.to_string())
                .or_insert_with(|| callee.id.as_str().to_string());
        }
    }
    instances.retain(|name, _| writes.get(name).copied() == Some(1));
    instances
}

/// Arity verdict for a resolved call, `None` when the argument list matches
/// or cannot be judged (`*args`/`**kwargs` unpacking disables the check).
pub(crate) enum S930ArityProblem {
    TooMany { extra: usize, expected: usize },
    Missing { missing: usize, expected: usize },
    MissingKeywordOnly,
}

pub(crate) fn s930_arity_problem(
    resolved: &ResolvedCallee,
    arguments: &ruff_python_ast::Arguments,
) -> Option<S930ArityProblem> {
    if arguments
        .args
        .iter()
        .any(|arg| matches!(arg, Expr::Starred(_)))
        || arguments
            .keywords
            .iter()
            .any(|keyword| keyword.arg.is_none())
    {
        return None;
    }
    let parameters = &resolved.function().parameters;
    let entries = parameter_entries(parameters, resolved.skips_receiver());
    let required = entries
        .iter()
        .filter(|entry| entry.default.is_none())
        .count();
    let positional_count = arguments.args.len();
    let keyword_names: Vec<Option<&str>> = arguments
        .keywords
        .iter()
        .map(|keyword| {
            keyword
                .arg
                .as_ref()
                .map(ruff_python_ast::Identifier::as_str)
        })
        .collect();
    if parameters.vararg.is_none() && positional_count > entries.len() {
        return Some(S930ArityProblem::TooMany {
            extra: positional_count - entries.len(),
            expected: entries.len(),
        });
    }
    let mut missing = required.saturating_sub(positional_count);
    for name in keyword_names.iter().flatten() {
        if entries
            .iter()
            .take(required)
            .any(|entry| entry.parameter.name.as_str() == *name)
        {
            missing = missing.saturating_sub(1);
        }
    }
    if missing > 0 {
        return Some(S930ArityProblem::Missing {
            missing,
            expected: entries.len(),
        });
    }
    if parameters.kwarg.is_none()
        && parameters.kwonlyargs.iter().any(|entry| {
            entry.default.is_none() && !keyword_names.contains(&Some(entry.parameter.name.as_str()))
        })
    {
        return Some(S930ArityProblem::MissingKeywordOnly);
    }
    None
}

/// Checks one resolved call's positional and keyword arguments against the
/// callee's parameter annotations; variadic signatures disable the check.
pub(crate) fn s5655_check_call(
    resolved: &ResolvedCallee,
    call: &ruff_python_ast::ExprCall,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if call
        .arguments
        .args
        .iter()
        .any(|argument| matches!(argument, Expr::Starred(_)))
    {
        return;
    }
    let parameters = &resolved.function().parameters;
    let function_name = resolved.function().name.as_str();
    if parameters.vararg.is_some() || parameters.kwarg.is_some() {
        return;
    }
    let entries = parameter_entries(parameters, resolved.skips_receiver());
    for (position, argument) in call.arguments.args.iter().enumerate() {
        match entries.get(position) {
            Some(entry) => {
                s5655_check_argument(function_name, entry, argument, issues, index, source);
            }
            None => break,
        }
    }
    for keyword in &call.arguments.keywords {
        let Some(name) = keyword.arg.as_deref() else {
            continue;
        };
        let matched = entries
            .iter()
            .copied()
            .chain(parameters.kwonlyargs.iter())
            .find(|entry| entry.parameter.name.as_str() == name);
        if let Some(entry) = matched {
            s5655_check_argument(function_name, entry, &keyword.value, issues, index, source);
        }
    }
}

/// Normalized signature shape used for override comparisons; the conventional
/// `self`/`cls` receiver is stripped and defaults are whitespace-normalized.
pub(crate) struct MethodShape {
    positional_names: Vec<String>,
    positional_defaults: Vec<Option<String>>,
    keyword_only: Vec<(String, Option<String>)>,
    has_vararg: bool,
    has_keyword_vararg: bool,
}

pub(crate) fn method_shape(
    function: &ruff_python_ast::StmtFunctionDef,
    source: &str,
) -> MethodShape {
    let parameters = &function.parameters;
    let mut entries: Vec<&ruff_python_ast::ParameterWithDefault> = parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .collect();
    if entries.first().is_some_and(|entry| {
        let name = entry.parameter.name.as_str();
        name == "self" || name == "cls"
    }) {
        entries.remove(0);
    }
    MethodShape {
        positional_names: entries
            .iter()
            .map(|entry| entry.parameter.name.as_str().to_string())
            .collect(),
        positional_defaults: entries
            .iter()
            .map(|entry| {
                entry
                    .default
                    .as_ref()
                    .map(|default| expr_normalized_text(default, source))
            })
            .collect(),
        keyword_only: parameters
            .kwonlyargs
            .iter()
            .map(|entry| {
                (
                    entry.parameter.name.as_str().to_string(),
                    entry
                        .default
                        .as_ref()
                        .map(|default| expr_normalized_text(default, source)),
                )
            })
            .collect(),
        has_vararg: parameters.vararg.is_some(),
        has_keyword_vararg: parameters.kwarg.is_some(),
    }
}

/// First contract-breaking difference of an override, `None` when compatible
/// (adding optional parameters, relaxing defaults, adding variadics).
pub(crate) fn s2638_contract_change(
    base: &MethodShape,
    derived: &MethodShape,
) -> Option<&'static str> {
    let variadic_change = variadic_contract_change(base, derived);
    if variadic_change.is_some() {
        return variadic_change;
    }
    if base.has_vararg
        || base.has_keyword_vararg
        || derived.has_vararg
        || derived.has_keyword_vararg
    {
        return None;
    }
    positional_contract_change(base, derived).or_else(|| keyword_contract_change(base, derived))
}

fn variadic_contract_change(base: &MethodShape, derived: &MethodShape) -> Option<&'static str> {
    if base.has_vararg && !derived.has_vararg {
        Some("it removes '*args'")
    } else if base.has_keyword_vararg && !derived.has_keyword_vararg {
        Some("it removes '**kwargs'")
    } else {
        None
    }
}

fn positional_contract_change(base: &MethodShape, derived: &MethodShape) -> Option<&'static str> {
    let shared = base
        .positional_names
        .len()
        .min(derived.positional_names.len());
    for index in 0..shared {
        if base.positional_names[index] != derived.positional_names[index] {
            return Some("it renames a parameter");
        }
        match (
            &base.positional_defaults[index],
            &derived.positional_defaults[index],
        ) {
            (Some(base_default), derived_default)
                if Some(base_default) != derived_default.as_ref() =>
            {
                return Some("it changes a parameter's default");
            }
            _ => {}
        }
    }
    if derived.positional_defaults[shared..]
        .iter()
        .any(Option::is_none)
    {
        return Some("it adds a required parameter");
    }
    if base.positional_defaults[shared..]
        .iter()
        .any(Option::is_none)
    {
        return Some("it drops a required parameter");
    }
    None
}

fn keyword_contract_change(base: &MethodShape, derived: &MethodShape) -> Option<&'static str> {
    for (name, base_default) in &base.keyword_only {
        match derived
            .keyword_only
            .iter()
            .find(|(derived_name, _)| derived_name == name)
        {
            None => {
                if base_default.is_none() {
                    return Some("it drops a required keyword-only parameter");
                }
            }
            Some((_, derived_default)) => match (base_default, derived_default) {
                (Some(base_value), derived_value) if Some(base_value) != derived_value.as_ref() => {
                    return Some("it changes a keyword-only parameter's default");
                }
                (Some(_), None) => {
                    return Some("it makes a keyword-only parameter required");
                }
                _ => {}
            },
        }
    }
    if derived.keyword_only.iter().any(|(name, default)| {
        default.is_none() && !base.keyword_only.iter().any(|(other, _)| other == name)
    }) {
        return Some("it adds a required keyword-only parameter");
    }
    None
}
