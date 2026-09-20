use std::collections::HashMap;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, ModModule, Stmt, StmtFor, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use crate::support::stmt_store_names;
use crate::support::{ImportFqns, NameResolution, WebFrameworkFacts};
use crate::support::{child_bodies, child_exprs};

const RULE_KEY: &str = "python:S8516";
const MESSAGE: &str =
    "Consume this group iterator inside the loop, or materialize it into a collection.";

/// Consumers that exhaust the iterator immediately — the reference's
/// `SAFE_CONSUMER_MATCHER` list.
const SAFE_CONSUMER_FQNS: &[&str] = &[
    "list",
    "tuple",
    "set",
    "frozenset",
    "sorted",
    "sum",
    "max",
    "min",
    "any",
    "all",
    "next",
    "len",
    "str.join",
    "bytes.join",
];

/// Builtin names the reference resolves to a known type. A known callee
/// outside `SAFE_CONSUMER_FQNS` keeps the sink chain walking; an unknown
/// callee is assumed safe to avoid false positives.
const KNOWN_BUILTIN_CALLEES: &[&str] = &[
    "abs",
    "all",
    "any",
    "bool",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "hasattr",
    "hash",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "map",
    "max",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "str",
    "sum",
    "tuple",
    "type",
    "vars",
    "zip",
];

/// Module roots the reference resolves through typeshed. Imports from
/// other roots are unknown and assumed safe.
const KNOWN_MODULE_ROOTS: &[&str] = &[
    "abc",
    "asyncio",
    "builtins",
    "collections",
    "copy",
    "csv",
    "dataclasses",
    "datetime",
    "enum",
    "functools",
    "heapq",
    "io",
    "itertools",
    "json",
    "logging",
    "math",
    "operator",
    "os",
    "pathlib",
    "pickle",
    "random",
    "re",
    "secrets",
    "shutil",
    "statistics",
    "string",
    "sys",
    "time",
    "typing",
    "typing_extensions",
    "unittest",
    "uuid",
];

/// Container methods that store their argument as a single element without
/// iterating it — the reference's `STORING_METHOD_NAMES`.
const STORING_METHOD_NAMES: &[&str] = &["append", "add", "setdefault"];

/// python:S8516 — `itertools.groupby` group iterators share the outer
/// iterator's data source and are invalidated when the loop advances, so a
/// read that escapes the iteration (assignment, `yield`, capture by a
/// nested function, or a storing-method argument) silently yields nothing.
/// The finding anchors on the escaping read.
pub(crate) fn check_s8516_groupby_iterator_reuse(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let fqns = ImportFqns::build(file_ctx);
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::For(for_stmt) = *stmt else {
            continue;
        };
        check_for_statement(for_stmt, &fqns, &facts, index, source, &mut issues);
    }
    issues
}

/// Flags each unsafe read of the group variable of a
/// `for key, group in groupby(...)` loop.
fn check_for_statement(
    for_stmt: &StmtFor,
    fqns: &ImportFqns,
    facts: &WebFrameworkFacts<'_>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Some(group) = group_loop_variable(for_stmt, fqns) else {
        return;
    };
    // Any rebinding of the group name in the loop's own scope makes the
    // usages ambiguous without a CFG — the reference bails the same way.
    if scope_binds(&for_stmt.body, group) {
        return;
    }
    let parents = ParentMap::build(&for_stmt.body);
    let mut reads = Vec::new();
    collect_reads(&for_stmt.body, group, false, &mut reads);
    for read in reads {
        if read.captured || reaches_sink(read.name.range(), &parents, fqns, facts) {
            issues.push(issue_at(
                RULE_KEY,
                MESSAGE,
                read.name.range(),
                index,
                source,
            ));
        }
    }
}

/// The group variable of `for <pair> in groupby(...)`: the second element
/// of a two-element tuple/list target when the iterable is a single
/// `itertools.groupby` call in any import spelling.
fn group_loop_variable<'a>(for_stmt: &'a StmtFor, fqns: &ImportFqns) -> Option<&'a str> {
    let Expr::Call(call) = for_stmt.iter.as_ref() else {
        return None;
    };
    if !fqns.is_fqn(&call.func, "itertools.groupby") {
        return None;
    }
    let elements = match for_stmt.target.as_ref() {
        Expr::Tuple(tuple) => tuple.elts.as_slice(),
        Expr::List(list) => list.elts.as_slice(),
        _ => return None,
    };
    let [_, Expr::Name(group)] = elements else {
        return None;
    };
    Some(group.id.as_str())
}

/// A read of the group name inside the loop body plus whether a nested
/// function or lambda captures it.
struct GroupRead<'a> {
    name: &'a ruff_python_ast::ExprName,
    captured: bool,
}

/// Collects reads of `group` in `stmts`, descending into nested scopes that
/// do not rebind the name. Reads inside a nested `def`/`lambda` are marked
/// captured — the reference flags them unconditionally because the closure
/// outlives the iteration.
fn collect_reads<'a>(
    stmts: &'a [Stmt],
    group: &str,
    captured: bool,
    reads: &mut Vec<GroupRead<'a>>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                if function_binds(function, group) {
                    continue;
                }
                collect_expr_reads(&stmt_exprs(stmt), group, true, reads);
                collect_reads(&function.body, group, true, reads);
            }
            Stmt::ClassDef(class) => {
                if scope_binds(&class.body, group) {
                    continue;
                }
                collect_expr_reads(&stmt_exprs(stmt), group, captured, reads);
                collect_reads(&class.body, group, captured, reads);
            }
            _ => {
                collect_expr_reads(&stmt_exprs(stmt), group, captured, reads);
                for body in child_bodies(stmt) {
                    collect_reads(body, group, captured, reads);
                }
            }
        }
    }
}

/// Collects reads of `group` inside expressions, honoring lambda and
/// comprehension binding scopes.
fn collect_expr_reads<'a>(
    exprs: &[&'a Expr],
    group: &str,
    captured: bool,
    reads: &mut Vec<GroupRead<'a>>,
) {
    let mut pending: Vec<(&Expr, bool)> = exprs.iter().map(|expr| (*expr, captured)).collect();
    while let Some((expr, captured)) = pending.pop() {
        match expr {
            Expr::Name(name) if name.id.as_str() == group => {
                reads.push(GroupRead { name, captured });
            }
            Expr::Named(named) if walrus_binds(named, group) => {}
            Expr::Lambda(lambda) => {
                if !lambda_binds(lambda, group) {
                    pending.extend(child_exprs(expr).into_iter().map(|child| (child, true)));
                }
            }
            Expr::ListComp(comp) => collect_comprehension(
                &[&comp.elt],
                &comp.generators,
                group,
                captured,
                reads,
                &mut pending,
            ),
            Expr::SetComp(comp) => collect_comprehension(
                &[&comp.elt],
                &comp.generators,
                group,
                captured,
                reads,
                &mut pending,
            ),
            Expr::Generator(comp) => collect_comprehension(
                &[&comp.elt],
                &comp.generators,
                group,
                captured,
                reads,
                &mut pending,
            ),
            Expr::DictComp(comp) => {
                let mut parts: Vec<&Expr> = Vec::with_capacity(2);
                if let Some(key) = comp.key.as_deref() {
                    parts.push(key);
                }
                parts.push(&comp.value);
                collect_comprehension(
                    &parts,
                    &comp.generators,
                    group,
                    captured,
                    reads,
                    &mut pending,
                )
            }
            _ => pending.extend(child_exprs(expr).into_iter().map(|child| (child, captured))),
        }
    }
}

/// Whether a `group := value` walrus binds the group name.
fn walrus_binds(named: &ruff_python_ast::ExprNamed, group: &str) -> bool {
    matches!(named.target.as_ref(), Expr::Name(name) if name.id.as_str() == group)
}

/// Whether a nested `def` binds `group` locally: a parameter, a direct
/// body store, or a walrus inside its own scope.
fn function_binds(function: &StmtFunctionDef, group: &str) -> bool {
    parameters_include(&function.parameters, group) || scope_binds(&function.body, group)
}

/// Whether a lambda binds `group`: a parameter or a walrus in its body
/// outside nested lambdas.
fn lambda_binds(lambda: &ruff_python_ast::ExprLambda, group: &str) -> bool {
    if lambda
        .parameters
        .as_deref()
        .is_some_and(|parameters| parameters_include(parameters, group))
    {
        return true;
    }
    let mut found = false;
    let mut pending = vec![lambda.body.as_ref()];
    while let Some(expr) = pending.pop() {
        match expr {
            Expr::Lambda(_) => {}
            Expr::Named(named) if walrus_binds(named, group) => found = true,
            _ => pending.extend(child_exprs(expr)),
        }
    }
    found
}

/// Whether `stmts` bind `name` in their own scope — assignment, deletion,
/// loop/`with` targets, imports, defs, `global`/`nonlocal`, or a walrus —
/// without descending into nested function/class scopes.
fn scope_binds(stmts: &[Stmt], name: &str) -> bool {
    let mut pending: Vec<&Stmt> = stmts.iter().collect();
    while let Some(stmt) = pending.pop() {
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        if stmt_store_names(stmt).iter().any(|stored| stored == name) {
            return true;
        }
        if scope_walrus_binds(stmt, name) {
            return true;
        }
        pending.extend(child_bodies(stmt).into_iter().flatten());
    }
    false
}

/// Whether `parameters` declares `name` (positional, keyword-only,
/// `*args`, or `**kwargs`) — the same predicate the closure-capture rule
/// uses for loop-variable parameters.
fn parameters_include(parameters: &ruff_python_ast::Parameters, name: &str) -> bool {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .any(|param| param.parameter.name.as_str() == name)
        || parameters
            .vararg
            .as_ref()
            .is_some_and(|param| param.name.as_str() == name)
        || parameters
            .kwarg
            .as_ref()
            .is_some_and(|param| param.name.as_str() == name)
}

/// Whether a statement's own expressions contain a `name := ...` walrus
/// outside nested lambdas (walrus targets bind the enclosing scope).
fn scope_walrus_binds(stmt: &Stmt, name: &str) -> bool {
    let mut found = false;
    let mut pending: Vec<&Expr> = stmt_exprs(stmt);
    while let Some(expr) = pending.pop() {
        match expr {
            Expr::Lambda(_) => {}
            Expr::Named(named) if walrus_binds(named, name) => found = true,
            _ => pending.extend(child_exprs(expr)),
        }
    }
    found
}

/// Collects reads inside a comprehension, skipping generators whose
/// target rebinds `group` (those reads see the inner binding).
fn collect_comprehension<'a>(
    results: &[&'a Expr],
    generators: &'a [ruff_python_ast::Comprehension],
    group: &str,
    captured: bool,
    reads: &mut Vec<GroupRead<'a>>,
    pending: &mut Vec<(&'a Expr, bool)>,
) {
    collect_expr_reads(results, group, captured, reads);
    for generator in generators {
        if target_binds(&generator.target, group) {
            continue;
        }
        pending.extend(
            std::iter::once(&generator.iter)
                .chain(generator.ifs.iter())
                .map(|expr| (expr, captured)),
        );
    }
}

/// Whether a comprehension/for target binds `name` anywhere in its shape.
fn target_binds(target: &Expr, name: &str) -> bool {
    let mut names = Vec::new();
    crate::support::collect_target_names(target, &mut names);
    names.iter().any(|bound| bound == name)
}

/// The parent role of an expression for sink detection: assignment value,
/// yielded value, or positional call argument (with the owning call).
/// Every other parent is a non-sink.
#[derive(Clone, Copy)]
enum Parent {
    AssignValue,
    Yield,
    PositionalArg(TextSize),
}

/// Maps each expression's start offset to its sink-relevant parent role and
/// each call's start offset to the call node, covering the loop body.
struct ParentMap<'a> {
    expr_parents: HashMap<TextSize, Parent>,
    calls: HashMap<TextSize, &'a ExprCall>,
}

impl<'a> ParentMap<'a> {
    fn build(body: &'a [Stmt]) -> Self {
        let mut map = ParentMap {
            expr_parents: HashMap::new(),
            calls: HashMap::new(),
        };
        let mut pending: Vec<&Stmt> = body.iter().collect();
        while let Some(stmt) = pending.pop() {
            map.record_stmt(stmt);
            pending.extend(child_bodies(stmt).into_iter().flatten());
        }
        map
    }

    fn record_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::Assign(assign) => {
                self.expr_parents
                    .insert(assign.value.range().start(), Parent::AssignValue);
            }
            Stmt::Expr(expr_stmt) => {
                if let Expr::Yield(yield_expr) = expr_stmt.value.as_ref()
                    && let Some(value) = yield_expr.value.as_deref()
                {
                    self.expr_parents
                        .insert(value.range().start(), Parent::Yield);
                }
            }
            _ => {}
        }
        for expr in stmt_exprs(stmt) {
            self.record_expr(expr);
        }
    }

    fn record_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Yield(yield_expr) => {
                if let Some(value) = yield_expr.value.as_deref() {
                    self.expr_parents
                        .insert(value.range().start(), Parent::Yield);
                }
            }
            Expr::Call(call) => {
                self.calls.insert(call.range().start(), call);
                for arg in &call.arguments.args {
                    self.expr_parents.insert(
                        arg.range().start(),
                        Parent::PositionalArg(call.range().start()),
                    );
                }
            }
            _ => {}
        }
        for child in child_exprs(expr) {
            self.record_expr(child);
        }
    }

    fn parent_of(&self, range: TextRange) -> Option<Parent> {
        self.expr_parents.get(&range.start()).copied()
    }

    fn call_at(&self, start: TextSize) -> Option<&'a ExprCall> {
        self.calls.get(&start).copied()
    }
}

/// The reference's `reachesSink`: an assignment value or `yield` is a sink;
/// a positional argument delegates to `chainReachesSink` on the owning
/// call; keyword arguments and every other parent are safe.
fn reaches_sink(
    range: TextRange,
    parents: &ParentMap<'_>,
    fqns: &ImportFqns,
    facts: &WebFrameworkFacts<'_>,
) -> bool {
    match parents.parent_of(range) {
        Some(Parent::AssignValue | Parent::Yield) => true,
        Some(Parent::PositionalArg(call_start)) => parents
            .call_at(call_start)
            .is_some_and(|call| chain_reaches_sink(call, parents, fqns, facts)),
        _ => false,
    }
}

/// The reference's `chainReachesSink`: a safe consumer absorbs the chain, a
/// storing-method call is a sink, and anything else keeps walking from the
/// call itself.
fn chain_reaches_sink(
    call: &ExprCall,
    parents: &ParentMap<'_>,
    fqns: &ImportFqns,
    facts: &WebFrameworkFacts<'_>,
) -> bool {
    if is_safe_consumer_callee(&call.func, fqns, facts) {
        return false;
    }
    if is_storing_method_call(call) {
        return true;
    }
    reaches_sink(call.range(), parents, fqns, facts)
}

/// Whether the callee is a known non-consumer or a known container method
/// receiver — the reference's `!SAFE_CONSUMER_MATCHER.evaluateFor(...).
/// isFalse() || !RUNTIME_CLASS_OBJECT_MATCHER...isFalse()` inverted: a
/// callee is safe unless it provably resolves to something that is neither
/// a safe consumer nor a runtime class object.
fn is_safe_consumer_callee(func: &Expr, fqns: &ImportFqns, facts: &WebFrameworkFacts<'_>) -> bool {
    match func {
        Expr::Name(name) => match facts.resolve_name(name.id.as_str(), name.range()) {
            NameResolution::Import(fqn) => !known_module_member(&fqn),
            NameResolution::Value(value) => value_callee_safe(value, fqns, facts),
            NameResolution::Bound => true,
            NameResolution::Unbound => {
                !KNOWN_BUILTIN_CALLEES.contains(&name.id.as_str())
                    || SAFE_CONSUMER_FQNS.contains(&name.id.as_str())
                    || name.id.as_str() == "type"
            }
        },
        Expr::Attribute(attribute) => attribute_callee_safe(attribute, fqns, facts),
        _ => true,
    }
}

/// A `name = value` alias used as a callee: the value's own safety.
fn value_callee_safe(value: &Expr, fqns: &ImportFqns, facts: &WebFrameworkFacts<'_>) -> bool {
    match value {
        Expr::Call(call) => {
            // `Cls = type(...)`: the bound name is a runtime class object.
            is_type_call(&call.func, fqns, facts)
        }
        Expr::Name(_) | Expr::Attribute(_) => is_safe_consumer_callee(value, fqns, facts),
        Expr::Lambda(_) => false,
        _ => true,
    }
}

/// Whether `func` is the `type` builtin in any resolvable spelling.
fn is_type_call(func: &Expr, fqns: &ImportFqns, facts: &WebFrameworkFacts<'_>) -> bool {
    match func {
        Expr::Name(name) => match facts.resolve_name(name.id.as_str(), name.range()) {
            NameResolution::Unbound => name.id.as_str() == "type",
            NameResolution::Import(fqn) => fqn == "builtins.type",
            _ => false,
        },
        _ => fqns.is_fqn(func, "builtins.type"),
    }
}

/// Attribute callees: `str`/`bytes` `join` on a literal qualifier is a safe
/// consumer; a qualifier provably holding a container (literal or
/// constructor) makes the method known and unsafe; a `type(...)` qualifier
/// is a runtime class object and safe; anything else is unknown and safe.
fn attribute_callee_safe(
    attribute: &ruff_python_ast::ExprAttribute,
    fqns: &ImportFqns,
    facts: &WebFrameworkFacts<'_>,
) -> bool {
    let qualifier = attribute.value.as_ref();
    if matches!(attribute.attr.as_str(), "join")
        && matches!(qualifier, Expr::StringLiteral(_) | Expr::BytesLiteral(_))
    {
        return true;
    }
    if let Expr::Call(call) = qualifier
        && is_type_call(&call.func, fqns, facts)
    {
        return true;
    }
    if let Expr::Name(name) = qualifier {
        return match facts.resolve_name(name.id.as_str(), name.range()) {
            NameResolution::Import(fqn) => !known_module_member(&fqn),
            NameResolution::Value(value) => !is_container_value(value, fqns, facts),
            NameResolution::Bound | NameResolution::Unbound => true,
        };
    }
    if matches!(qualifier, Expr::List(_) | Expr::Dict(_) | Expr::Set(_)) {
        return false;
    }
    true
}

/// Whether a bound value is a container literal or a container-constructor
/// call, making `value.append`/`add`/`setdefault` resolvable.
fn is_container_value(value: &Expr, fqns: &ImportFqns, facts: &WebFrameworkFacts<'_>) -> bool {
    match value {
        Expr::List(_) | Expr::Dict(_) | Expr::Set(_) => true,
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Name(name) => {
                matches!(
                    facts.resolve_name(name.id.as_str(), name.range()),
                    NameResolution::Unbound
                ) && matches!(name.id.as_str(), "list" | "dict" | "set" | "bytearray")
            }
            func => fqns.is_fqn_in(
                func,
                &[
                    "builtins.list",
                    "builtins.dict",
                    "builtins.set",
                    "builtins.bytearray",
                ],
            ),
        },
        _ => false,
    }
}

/// Whether an imported member resolves to a known module (so a non-safe
/// member keeps the chain walking) — unknown modules stay safe.
fn known_module_member(fqn: &str) -> bool {
    fqn.split('.')
        .next()
        .is_some_and(|root| KNOWN_MODULE_ROOTS.contains(&root))
}

/// `x.append(group)`/`add`/`setdefault` — the reference's name-only storing
/// check, reached only when the callee is known (container qualifier).
fn is_storing_method_call(call: &ExprCall) -> bool {
    matches!(call.func.as_ref(), Expr::Attribute(attribute) if STORING_METHOD_NAMES.contains(&attribute.attr.as_str()))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8516_flags_stored_group_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "from itertools import groupby\n",
            "\n",
            "data = [1, 1, 2, 2, 3]\n",
            "groups = {}\n",
            "for key, group in groupby(data):\n",
            "    groups[key] = group  # Noncompliant\n",
            "for key, group in groups.items():\n",
            "    print(f\"{key}: {list(group)}\")  # Empty results\n",
        ));
        let found = findings(&flagged, "python:S8516");
        assert_eq!(found.len(), 1);
        // The anchor covers the escaping `group` read.
        assert_eq!(found[0].range.start, pos(6, 18));
        assert_eq!(found[0].range.end, pos(6, 23));
        assert_eq!(
            found[0].message,
            "Consume this group iterator inside the loop, or materialize it into a collection."
        );
    }

    #[test]
    fn s8516_accepts_materialized_group_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "from itertools import groupby\n",
            "\n",
            "data = [1, 1, 2, 2, 3]\n",
            "groups = {}\n",
            "for key, group in groupby(data):\n",
            "    groups[key] = list(group)  # Convert to list immediately\n",
            "for key, group in groups.items():\n",
            "    print(f\"{key}: {group}\")  # Correct results\n",
        ));
        assert!(findings(&clean, "python:S8516").is_empty());
    }

    #[test]
    fn s8516_flags_yield_capture_and_storing_methods() {
        let flagged = scan(concat!(
            "from itertools import groupby\n",
            "\n",
            "def yielded(data):\n",
            "    for key, group in groupby(data):\n",
            "        yield group\n",
            "\n",
            "def captured(data):\n",
            "    fns = []\n",
            "    for key, group in groupby(data):\n",
            "        fns.append(lambda: list(group))\n",
            "\n",
            "def stored(data):\n",
            "    seen = set()\n",
            "    cache = {}\n",
            "    for key, group in groupby(data):\n",
            "        seen.add(group)\n",
            "        cache.setdefault(key, group)\n",
            "        it = enumerate(group)\n",
        ));
        assert_eq!(findings(&flagged, "python:S8516").len(), 5);
    }

    #[test]
    fn s8516_flags_lazy_passthrough_into_storing_method() {
        let flagged = scan(concat!(
            "from itertools import groupby\n",
            "from operator import itemgetter\n",
            "\n",
            "def collect(data):\n",
            "    out = []\n",
            "    for key, group in groupby(data):\n",
            "        out.append(map(itemgetter(0), group))\n",
        ));
        assert_eq!(findings(&flagged, "python:S8516").len(), 1);
    }

    #[test]
    fn s8516_flags_aliased_groupby_import() {
        let flagged = scan(concat!(
            "from itertools import groupby as gb\n",
            "\n",
            "def collect(data):\n",
            "    groups = {}\n",
            "    for key, group in gb(data):\n",
            "        groups[key] = group\n",
        ));
        assert_eq!(findings(&flagged, "python:S8516").len(), 1);
    }

    #[test]
    fn s8516_accepts_consumed_and_safe_uses() {
        let clean = scan(concat!(
            "from itertools import groupby\n",
            "\n",
            "def consumed(data):\n",
            "    for key, group in groupby(data):\n",
            "        for item in group:\n",
            "            print(item)\n",
            "        joined = \",\".join(group)\n",
            "        print(group)\n",
            "        result = list(iterable=group)\n",
            "        out = []\n",
            "        out.extend(group)\n",
            "        keys = list(map(str, group))\n",
            "        for subkey, subgroup in groupby(group):\n",
            "            print(subkey, list(subgroup))\n",
            "\n",
            "def runtime_class(data):\n",
            "    container_class = type([])\n",
            "    for key, group in groupby(data):\n",
            "        container = container_class(group)\n",
        ));
        assert!(findings(&clean, "python:S8516").is_empty());
    }

    #[test]
    fn s8516_skips_rebound_and_non_groupby_loops() {
        let clean = scan(concat!(
            "from itertools import groupby\n",
            "\n",
            "def rebound(data):\n",
            "    groups = {}\n",
            "    for key, group in groupby(data):\n",
            "        groups[key] = group\n",
            "        group = list(group)\n",
            "\n",
            "def not_groupby(data):\n",
            "    groups = {}\n",
            "    for key, group in data:\n",
            "        groups[key] = group\n",
            "\n",
            "def single_target(data):\n",
            "    for pair in groupby(data):\n",
            "        saved = pair\n",
        ));
        assert!(findings(&clean, "python:S8516").is_empty());
    }

    #[test]
    fn s8516_accepts_unknown_callee_and_else_clause() {
        let clean = scan(concat!(
            "from itertools import groupby\n",
            "from nonexistent_module import safe_consumer\n",
            "\n",
            "def unresolved(data):\n",
            "    for key, group in groupby(data):\n",
            "        result = safe_consumer(group)\n",
            "\n",
            "def else_clause(data):\n",
            "    saved = None\n",
            "    for key, group in groupby(data):\n",
            "        pass\n",
            "    else:\n",
            "        saved = group\n",
            "\n",
            "def container_literal(data):\n",
            "    for key, group in groupby(data):\n",
            "        return [group]\n",
        ));
        assert!(findings(&clean, "python:S8516").is_empty());
    }
}
