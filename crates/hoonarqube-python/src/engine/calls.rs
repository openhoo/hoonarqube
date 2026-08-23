use crate::support::direct_base_names;
use crate::support::expr_normalized_text;
use crate::support::has_decorator;
use crate::support::parameter_entries;
use crate::support::s5655_check_argument;
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
        let mut functions: HashMap<String, &'a ruff_python_ast::StmtFunctionDef> = HashMap::new();
        let mut classes: HashMap<String, &'a ruff_python_ast::StmtClassDef> = HashMap::new();
        let mut ambiguous: HashSet<String> = HashSet::new();
        for stmt in module {
            match stmt {
                Stmt::FunctionDef(function) => {
                    let name = function.name.as_str();
                    if functions.remove(name).is_some() || !ambiguous.insert(name.to_string()) {
                        continue;
                    }
                    functions.insert(name.to_string(), function);
                }
                Stmt::ClassDef(class) => {
                    let name = class.name.as_str();
                    if classes.remove(name).is_some() || !ambiguous.insert(name.to_string()) {
                        continue;
                    }
                    classes.insert(name.to_string(), class);
                }
                _ => {}
            }
        }
        let mut instances: HashMap<String, String> = HashMap::new();
        let mut conflicted: HashSet<String> = HashSet::new();
        let mut writes: HashMap<String, usize> = HashMap::new();
        for stmt in module {
            for name in stmt_store_names(stmt) {
                *writes.entry(name).or_insert(0) += 1;
            }
            if let Stmt::Assign(assign) = stmt
                && let [target] = assign.targets.as_slice()
                && let Expr::Name(name) = target
                && let Expr::Call(call) = assign.value.as_ref()
                && let Expr::Name(callee) = call.func.as_ref()
                && classes.contains_key(callee.id.as_str())
            {
                let key = name.id.as_str();
                match instances.get(key) {
                    Some(_) => {
                        conflicted.insert(key.to_string());
                    }
                    None => {
                        instances.insert(key.to_string(), callee.id.as_str().to_string());
                    }
                }
            }
        }
        instances.retain(|name, _| writes.get(name).copied() == Some(1));
        for name in conflicted {
            instances.remove(&name);
        }
        Self {
            functions,
            classes,
            instances,
        }
    }

    /// Nearest declaration of `method` walking the file-local base chain of
    /// `class_name`; cycles are cut by the visited set.
    fn nearest_method(&self, class_name: &str, method: &str) -> Option<ResolvedCallee<'a>> {
        self.nearest_method_in(class_name, method, &mut HashSet::new())
    }

    fn nearest_method_in(
        &self,
        class_name: &str,
        method: &str,
        visited: &mut HashSet<String>,
    ) -> Option<ResolvedCallee<'a>> {
        if !visited.insert(class_name.to_string()) {
            return None;
        }
        let class = self.classes.get(class_name)?;
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
        for base in direct_base_names(class) {
            if let Some(found) = self.nearest_method_in(base, method, visited) {
                return Some(found);
            }
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

/// Arity verdict for a resolved call, `None` when the argument list matches
/// or cannot be judged (`*args`/`**kwargs` unpacking disables the check).
pub(crate) fn s930_arity_problem(
    resolved: &ResolvedCallee,
    arguments: &ruff_python_ast::Arguments,
) -> Option<&'static str> {
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
        return Some("too many arguments");
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
        return Some("missing required arguments");
    }
    if parameters.kwarg.is_none()
        && parameters.kwonlyargs.iter().any(|entry| {
            entry.default.is_none() && !keyword_names.contains(&Some(entry.parameter.name.as_str()))
        })
    {
        return Some("missing required keyword-only arguments");
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
    if parameters.vararg.is_some() || parameters.kwarg.is_some() {
        return;
    }
    let entries = parameter_entries(parameters, resolved.skips_receiver());
    for (position, argument) in call.arguments.args.iter().enumerate() {
        match entries.get(position) {
            Some(entry) => {
                s5655_check_argument(entry, argument, issues, index, source);
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
            s5655_check_argument(entry, &keyword.value, issues, index, source);
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
    if base.has_vararg && !derived.has_vararg {
        return Some("it removes '*args'");
    }
    if base.has_keyword_vararg && !derived.has_keyword_vararg {
        return Some("it removes '**kwargs'");
    }
    if base.has_vararg
        || base.has_keyword_vararg
        || derived.has_vararg
        || derived.has_keyword_vararg
    {
        return None;
    }
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
