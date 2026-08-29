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
use ruff_python_ast::Pattern;
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
        Expr::Subscript(subscript) => annotation_root_name(&subscript.value)?,
        other => annotation_root_name(other)?,
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

fn annotation_root_name(annotation: &Expr) -> Option<&str> {
    match annotation {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => {
            let Expr::Name(owner) = attribute.value.as_ref() else {
                return None;
            };
            let attribute_name = attribute.attr.as_str();
            match owner.id.as_str() {
                "builtins"
                    if matches!(
                        attribute_name,
                        "int"
                            | "float"
                            | "complex"
                            | "str"
                            | "bytes"
                            | "bool"
                            | "list"
                            | "set"
                            | "dict"
                            | "tuple"
                            | "frozenset"
                    ) =>
                {
                    Some(attribute_name)
                }
                "typing"
                    if matches!(
                        attribute_name,
                        "List" | "Set" | "Dict" | "Tuple" | "FrozenSet"
                    ) =>
                {
                    Some(attribute_name)
                }
                _ => None,
            }
        }
        _ => None,
    }
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

    /// Nearest declaration of `method` in the file-local Python C3 order.
    /// Cycles, inconsistent hierarchies, and unknown bases fail closed.
    fn nearest_method(
        &self,
        class_name: &str,
        method: &str,
    ) -> Option<&'a ruff_python_ast::StmtFunctionDef> {
        let class = self.classes.get(class_name)?;
        if let Some(function) = declared_method(class, method) {
            return Some(function);
        }
        for inherited_name in self
            .method_resolution_order(class_name)?
            .into_iter()
            .skip(1)
        {
            let class = self.classes.get(inherited_name.as_str())?;
            if let Some(function) = declared_method(class, method) {
                return Some(function);
            }
        }
        None
    }

    /// File-local Python C3 method-resolution order. Straight inheritance
    /// chains use a linear fast path; only actual branching builds merge
    /// tables. Unknown/dynamic bases fail closed instead of guessing an order.
    fn method_resolution_order(&self, class_name: &str) -> Option<Vec<String>> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = class_name.to_string();
        loop {
            if !visited.insert(current.clone()) {
                return None;
            }
            chain.push(current.clone());
            let class = self.classes.get(current.as_str())?;
            let bases = self.local_base_names(class)?;
            match bases.as_slice() {
                [] => return Some(chain),
                [base] => current.clone_from(base),
                _ => return self.c3_method_resolution_order(class_name),
            }
        }
    }

    fn local_base_names(&self, class: &ruff_python_ast::StmtClassDef) -> Option<Vec<String>> {
        let Some(arguments) = class.arguments.as_deref() else {
            return Some(Vec::new());
        };
        let bases = direct_base_names(class);
        if bases.len() != arguments.args.len()
            || bases.iter().any(|base| !self.classes.contains_key(*base))
        {
            return None;
        }
        Some(bases.into_iter().map(str::to_string).collect())
    }

    fn c3_method_resolution_order(&self, root: &str) -> Option<Vec<String>> {
        let mut state: HashMap<String, bool> = HashMap::new();
        let mut pending = vec![(root.to_string(), false)];
        let mut postorder = Vec::new();
        while let Some((name, expanded)) = pending.pop() {
            if expanded {
                state.insert(name.clone(), true);
                postorder.push(name);
                continue;
            }
            match state.get(&name) {
                Some(true) => continue,
                Some(false) => return None,
                None => {}
            }
            state.insert(name.clone(), false);
            let bases = self.local_base_names(self.classes.get(name.as_str())?)?;
            pending.push((name, true));
            for base in bases.into_iter().rev() {
                pending.push((base, false));
            }
        }

        let mut mros: HashMap<String, Vec<String>> = HashMap::new();
        for name in postorder {
            let bases = self.local_base_names(self.classes.get(name.as_str())?)?;
            let mut sequences: Vec<Vec<String>> = bases
                .iter()
                .map(|base| mros.get(base).cloned())
                .collect::<Option<_>>()?;
            sequences.push(bases);
            let mut mro = vec![name.clone()];
            mro.extend(c3_merge(&sequences)?);
            mros.insert(name, mro);
        }
        mros.remove(root)
    }

    /// Resolves a call's callee expression against the tables.
    pub(crate) fn resolve(
        &self,
        func: &Expr,
        class_context: Option<&str>,
    ) -> Option<ResolvedCallee<'a>> {
        match func {
            Expr::Name(callee) => self.resolve_name_callee(callee.id.as_str()),
            Expr::Attribute(attribute) => self.resolve_attribute_callee(attribute, class_context),
            _ => None,
        }
    }

    fn resolve_name_callee(&self, name: &str) -> Option<ResolvedCallee<'a>> {
        if let Some(function) = self.functions.get(name) {
            return Some(ResolvedCallee::Function(function));
        }
        self.classes
            .contains_key(name)
            .then(|| self.resolve_bound_method(name, "__init__"))?
    }

    fn resolve_attribute_callee(
        &self,
        attribute: &ruff_python_ast::ExprAttribute,
        class_context: Option<&str>,
    ) -> Option<ResolvedCallee<'a>> {
        let Expr::Name(owner) = attribute.value.as_ref() else {
            return None;
        };
        let owner = owner.id.as_str();
        let method = attribute.attr.as_str();
        if matches!(owner, "self" | "cls") {
            return self.resolve_bound_method(class_context?, method);
        }
        if let Some(class_name) = self.instances.get(owner) {
            return self.resolve_bound_method(class_name, method);
        }
        self.classes
            .contains_key(owner)
            .then(|| self.resolve_class_method(owner, method))?
    }

    fn resolve_bound_method(&self, class_name: &str, method: &str) -> Option<ResolvedCallee<'a>> {
        let function = self.nearest_method(class_name, method)?;
        Some(ResolvedCallee::Bound(
            function,
            has_decorator(function, "staticmethod"),
        ))
    }

    fn resolve_class_method(&self, class_name: &str, method: &str) -> Option<ResolvedCallee<'a>> {
        let function = self.nearest_method(class_name, method)?;
        // Ordinary methods accessed through the class are unbound: callers
        // must supply `self`. Only a classmethod supplies the receiver.
        Some(if has_decorator(function, "classmethod") {
            ResolvedCallee::Bound(function, false)
        } else {
            ResolvedCallee::Function(function)
        })
    }
}

fn declared_method<'a>(
    class: &'a ruff_python_ast::StmtClassDef,
    method: &str,
) -> Option<&'a ruff_python_ast::StmtFunctionDef> {
    class.body.iter().find_map(|stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.name.as_str() == method
        {
            Some(function)
        } else {
            None
        }
    })
}

fn c3_merge(sequences: &[Vec<String>]) -> Option<Vec<String>> {
    let mut positions = vec![0usize; sequences.len()];
    let mut merged = Vec::new();
    while positions
        .iter()
        .enumerate()
        .any(|(index, position)| *position < sequences[index].len())
    {
        let candidate = sequences
            .iter()
            .enumerate()
            .filter_map(|(index, sequence)| sequence.get(positions[index]))
            .find(|candidate| {
                sequences.iter().enumerate().all(|(index, sequence)| {
                    let tail_start = positions[index].saturating_add(1).min(sequence.len());
                    !sequence[tail_start..].contains(candidate)
                })
            })?
            .clone();
        merged.push(candidate.clone());
        for (index, sequence) in sequences.iter().enumerate() {
            if sequence.get(positions[index]) == Some(&candidate) {
                positions[index] += 1;
            }
        }
    }
    Some(merged)
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
    count_direct_statement_writes(stmt, writes);
    count_except_handler_writes(stmt, writes);
    count_match_capture_writes(stmt, writes);
    count_statement_expression_writes(stmt, writes);
}

fn count_direct_statement_writes(stmt: &Stmt, writes: &mut HashMap<String, usize>) {
    // `global`/`nonlocal` declarations redirect later stores; they are not
    // writes by themselves. Counting them used to discard otherwise unique
    // module signatures.
    if !matches!(stmt, Stmt::Global(_) | Stmt::Nonlocal(_)) {
        add_writes(writes, stmt_store_names(stmt));
    }
}

fn count_except_handler_writes(stmt: &Stmt, writes: &mut HashMap<String, usize>) {
    if let Stmt::Try(try_stmt) = stmt {
        for handler in &try_stmt.handlers {
            let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
            if let Some(name) = &handler.name {
                add_writes(writes, vec![name.as_str().to_string()]);
            }
        }
    }
}

fn count_match_capture_writes(stmt: &Stmt, writes: &mut HashMap<String, usize>) {
    if let Stmt::Match(match_stmt) = stmt {
        let mut captures = HashSet::new();
        for case in &match_stmt.cases {
            collect_pattern_capture_names(&case.pattern, &mut captures);
        }
        add_writes(writes, captures.into_iter().collect());
    }
}

fn count_statement_expression_writes(stmt: &Stmt, writes: &mut HashMap<String, usize>) {
    let mut expressions = stmt_exprs(stmt);
    while let Some(expr) = expressions.pop() {
        if let Expr::Named(named) = expr {
            let mut names = Vec::new();
            collect_target_names(&named.target, &mut names);
            add_writes(writes, names);
        }
        if let Expr::Lambda(lambda) = expr {
            // Lambda defaults execute in module scope, but its body owns a
            // fresh function scope and must not invalidate module bindings.
            if let Some(parameters) = &lambda.parameters {
                crate::support::push_parameter_exprs(parameters, &mut expressions);
            }
        } else {
            expressions.extend(child_exprs(expr));
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
    UnexpectedKeyword,
    DuplicateArgument,
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
    let positional_count = arguments.args.len();
    if parameters.vararg.is_none() && positional_count > entries.len() {
        return Some(S930ArityProblem::TooMany {
            extra: positional_count - entries.len(),
            expected: entries.len(),
        });
    }

    let posonly_names: HashSet<&str> = parameters
        .posonlyargs
        .iter()
        .map(|entry| entry.parameter.name.as_str())
        .collect();
    let keyword_names = match s930_keyword_names(
        parameters,
        &entries,
        arguments,
        &posonly_names,
        positional_count,
    ) {
        Ok(names) => names,
        Err(problem) => return problem,
    };

    let missing =
        count_missing_positional(&entries, &posonly_names, &keyword_names, positional_count);
    if missing > 0 {
        return Some(S930ArityProblem::Missing {
            missing,
            expected: entries.len(),
        });
    }
    if parameters.kwonlyargs.iter().any(|entry| {
        entry.default.is_none() && !keyword_names.contains(entry.parameter.name.as_str())
    }) {
        return Some(S930ArityProblem::MissingKeywordOnly);
    }
    None
}

fn s930_keyword_names(
    parameters: &ruff_python_ast::Parameters,
    entries: &[&ruff_python_ast::ParameterWithDefault],
    arguments: &ruff_python_ast::Arguments,
    posonly_names: &HashSet<&str>,
    positional_count: usize,
) -> Result<HashSet<String>, Option<S930ArityProblem>> {
    let mut keyword_names = HashSet::new();
    for keyword in &arguments.keywords {
        let Some(name) = keyword.arg.as_deref() else {
            // Guarded above, but keep this helper fail-closed if the AST API
            // ever exposes an unpacking through another representation.
            return Err(None);
        };
        if !keyword_names.insert(name.to_string()) {
            return Err(Some(S930ArityProblem::DuplicateArgument));
        }
        if let Some(problem) =
            s930_keyword_problem(parameters, entries, posonly_names, positional_count, name)
        {
            return Err(Some(problem));
        }
    }
    Ok(keyword_names)
}

fn s930_keyword_problem(
    parameters: &ruff_python_ast::Parameters,
    entries: &[&ruff_python_ast::ParameterWithDefault],
    posonly_names: &HashSet<&str>,
    positional_count: usize,
    name: &str,
) -> Option<S930ArityProblem> {
    if let Some(index) = entries
        .iter()
        .position(|entry| entry.parameter.name.as_str() == name)
    {
        if posonly_names.contains(name) && parameters.kwarg.is_none() {
            return Some(S930ArityProblem::UnexpectedKeyword);
        }
        if !posonly_names.contains(name) && index < positional_count {
            return Some(S930ArityProblem::DuplicateArgument);
        }
        return None;
    }
    if parameters.kwarg.is_none()
        && !parameters
            .kwonlyargs
            .iter()
            .any(|entry| entry.parameter.name.as_str() == name)
    {
        return Some(S930ArityProblem::UnexpectedKeyword);
    }
    None
}

fn count_missing_positional(
    entries: &[&ruff_python_ast::ParameterWithDefault],
    posonly_names: &HashSet<&str>,
    keyword_names: &HashSet<String>,
    positional_count: usize,
) -> usize {
    entries
        .iter()
        .enumerate()
        .filter(|(index, entry)| {
            entry.default.is_none()
                && *index >= positional_count
                && (posonly_names.contains(entry.parameter.name.as_str())
                    || !keyword_names.contains(entry.parameter.name.as_str()))
        })
        .count()
}

/// Checks every argument whose fixed slot remains provable against the
/// callee's parameter annotation. Unpacking only hides affected later slots.
pub(crate) fn s5655_check_call(
    resolved: &ResolvedCallee,
    call: &ruff_python_ast::ExprCall,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let parameters = &resolved.function().parameters;
    let function_name = resolved.function().name.as_str();
    let entries = parameter_entries(parameters, resolved.skips_receiver());
    for (position, argument) in call.arguments.args.iter().enumerate() {
        if matches!(argument, Expr::Starred(_)) {
            // The unpacked length makes every following positional slot
            // unknowable, but fixed arguments before it remain checkable.
            break;
        }
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
            .filter(|entry| {
                !parameters
                    .posonlyargs
                    .iter()
                    .any(|posonly| posonly.parameter.name == entry.parameter.name)
            })
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
