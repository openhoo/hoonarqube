use std::collections::{BTreeSet, HashSet};

use ruff_python_ast::{Expr, ExprCall, ExprLambda, Parameters, StmtClassDef, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::{
    WebFrameworkFacts, is_fastapi_verb, issue_at, keyword_argument, nth_or_keyword_argument,
};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8411";

const DEPENDS_FQNS: [&str; 4] = [
    "fastapi.param_functions.Depends",
    "fastapi.param_functions.Security",
    "fastapi.Depends",
    "fastapi.Security",
];
const PATH_FQNS: [&str; 2] = ["fastapi.param_functions.Path", "fastapi.Path"];
const ANNOTATED_FQNS: [&str; 2] = ["typing.Annotated", "typing_extensions.Annotated"];
const APP_OR_ROUTER_FQNS: [&str; 4] = [
    "fastapi.FastAPI",
    "fastapi.applications.FastAPI",
    "fastapi.APIRouter",
    "fastapi.routing.APIRouter",
];
const APP_OR_ROUTER_NAMES: [&str; 6] = [
    "FastAPI",
    "fastapi.FastAPI",
    "fastapi.applications.FastAPI",
    "APIRouter",
    "fastapi.APIRouter",
    "fastapi.routing.APIRouter",
];

/// python:S8411 — `FastAPI` injects path values only into parameters whose
/// names match the `{param}` segments of the route path, declared either
/// on the path operation function or on one of its `Depends`/`Security`
/// dependencies (including `dependencies=[...]` lists on the route
/// decorator and on the `FastAPI()`/`APIRouter()` constructor). Sonar
/// flags the function name for every undeclared path parameter and for
/// every path parameter declared positional-only (before `/`). When any
/// parameter source is dynamic, unresolved, or an unsupported shape —
/// `**kwargs`, an unresolvable dependency target, a non-`Depends`/`Path`
/// call in a default or `Annotated` metadata, an unknown `Path(alias=)`
/// value, a decorated or inheriting dependency class — missing-parameter
/// findings are suppressed for that route while positional-only findings
/// still report.
pub(crate) fn check_s8411_path_parameters(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        for decorator in &function.decorator_list {
            let Expr::Call(decorator_call) = &decorator.expression else {
                continue;
            };
            if !facts
                .expr_fqn(&decorator_call.func)
                .is_some_and(|fqn| is_fastapi_verb(&fqn))
            {
                continue;
            }
            let path_params = extract_path_parameters(&facts, decorator_call);
            if path_params.is_empty() {
                continue;
            }
            let mut collector = DependencyCollector::new(&facts);
            collector.collect(function, decorator_call);
            report_issues(
                &collector,
                function,
                &path_params,
                index,
                source,
                &mut issues,
            );
        }
    }
    issues
}

/// Collects every parameter name `FastAPI` can inject for one route: the
/// path operation function's own parameters plus the parameters of every
/// resolvable dependency callable. `unresolved` mirrors Sonar's
/// `hasUnresolvedOrUnsupportedParameterSources` bailout flag.
struct DependencyCollector<'f, 'a> {
    facts: &'f WebFrameworkFacts<'a>,
    names: HashSet<String>,
    positional_only: HashSet<String>,
    visited_functions: HashSet<TextRange>,
    unresolved: bool,
}

impl<'f, 'a> DependencyCollector<'f, 'a> {
    fn new(facts: &'f WebFrameworkFacts<'a>) -> Self {
        DependencyCollector {
            facts,
            names: HashSet::new(),
            positional_only: HashSet::new(),
            visited_functions: HashSet::new(),
            unresolved: false,
        }
    }

    fn collect(&mut self, function: &'a StmtFunctionDef, decorator_call: &'a ExprCall) {
        self.visit_function(function, false, true);
        self.visit_dependencies_argument(decorator_call);
        self.visit_app_or_router_dependencies(decorator_call);
    }

    /// `FastAPI(dependencies=[...])` / `APIRouter(dependencies=[...])`
    /// apply to every route registered on the object, so the decorator's
    /// receiver (`router` in `@router.get(...)`) is another dependency
    /// entry point when it resolves to a constructor call.
    fn visit_app_or_router_dependencies(&mut self, decorator_call: &'a ExprCall) {
        let Expr::Attribute(attribute) = decorator_call.func.as_ref() else {
            return;
        };
        let receiver = self.resolve_alias_chain(&attribute.value);
        if let Expr::Call(call) = receiver
            && self.is_app_or_router_call(call)
        {
            self.visit_dependencies_argument(call);
        }
    }

    /// Inspects a `dependencies=[...]` keyword argument: each list/tuple
    /// element must resolve to a `Depends`/`Security` call; anything else
    /// (bare names, unpacking, other calls, literals) bails out.
    fn visit_dependencies_argument(&mut self, call: &'a ExprCall) {
        let Some(dependencies) = keyword_argument(call, "dependencies") else {
            return;
        };
        let resolved = self.resolve_alias_chain(dependencies);
        let elements: Vec<&'a Expr> = match resolved {
            Expr::List(list) => list.elts.iter().collect(),
            Expr::Tuple(tuple) => tuple.elts.iter().collect(),
            _ => {
                self.unresolved = true;
                return;
            }
        };
        for element in elements {
            self.visit_dependency_list_element(element);
        }
    }

    fn visit_dependency_list_element(&mut self, element: &'a Expr) {
        let dependency = self.resolve_alias_chain(element);
        match dependency {
            Expr::Call(call) if self.is_depends_call(call) => {
                self.visit_depends_call(call, None);
            }
            _ => self.unresolved = true,
        }
    }

    fn visit_function(
        &mut self,
        function: &'a StmtFunctionDef,
        skip_first: bool,
        record_positional_only: bool,
    ) {
        if !self.visited_functions.insert(function.range()) {
            return;
        }
        self.visit_parameters(&function.parameters, skip_first, record_positional_only);
    }

    fn visit_lambda(&mut self, lambda: &'a ExprLambda) {
        if let Some(parameters) = lambda.parameters.as_deref() {
            self.visit_parameters(parameters, false, false);
        }
    }

    /// Registers every parameter name; `*args` is ignored, `**kwargs`
    /// bails out, and parameters before `/` are recorded positional-only
    /// when `record_positional_only` (only the path operation function
    /// itself reports positional-only findings).
    fn visit_parameters(
        &mut self,
        parameters: &'a Parameters,
        skip_first: bool,
        record_positional_only: bool,
    ) {
        let entries = parameter_entries(parameters);
        for entry in entries.iter().skip(usize::from(skip_first)) {
            self.visit_parameter_entry(entry, record_positional_only);
        }
    }

    /// Registers one parameter: `*args` is ignored, `**kwargs` bails out,
    /// `Path(alias=...)` markers contribute their alias instead of the
    /// parameter name.
    fn visit_parameter_entry(&mut self, entry: &ParamEntry<'a>, record_positional_only: bool) {
        if let Some(stars) = entry.star {
            if stars == "**" {
                self.unresolved = true;
            }
            return;
        }
        let mut path_aliases: Vec<String> = Vec::new();
        let parameter_type = entry
            .parameter
            .annotation()
            .and_then(|annotation| self.visit_type_annotation(annotation, &mut path_aliases));
        if let Some(default) = entry.default {
            self.visit_dependency_marker(default, parameter_type, &mut path_aliases);
        }
        if path_aliases.is_empty() {
            self.names.insert(entry.parameter.name.as_str().to_string());
            if entry.positional_only && record_positional_only {
                self.positional_only
                    .insert(entry.parameter.name.as_str().to_string());
            }
        } else {
            for alias in path_aliases {
                self.names.insert(alias.clone());
                if entry.positional_only && record_positional_only {
                    self.positional_only.insert(alias);
                }
            }
        }
    }

    /// The parameter's declared type, used as the `Depends()` target when
    /// no explicit dependency is given. `Annotated[T, <metadata>]` yields
    /// `T` and feeds the metadata through the dependency-marker visitor;
    /// a name bound once to another annotation expression resolves as a
    /// type alias, with cycles bailing out.
    fn visit_type_annotation(
        &mut self,
        annotation: &'a Expr,
        path_aliases: &mut Vec<String>,
    ) -> Option<&'a Expr> {
        let mut visited_aliases: HashSet<TextRange> = HashSet::new();
        let mut expression = annotation;
        loop {
            if let Expr::Name(name) = expression
                && let Some((value, binding)) = self
                    .facts
                    .strict_single_assignment(name.id.as_str(), name.range())
            {
                if !visited_aliases.insert(binding) {
                    // Cyclic type alias (`A = B; B = A`): the chain may
                    // hide Annotated metadata.
                    self.unresolved = true;
                    return Some(expression);
                }
                expression = value;
                continue;
            }
            break;
        }
        if let Expr::Subscript(subscript) = expression
            && self.is_annotated_object(&subscript.value)
        {
            let elements = subscript_elements(&subscript.slice);
            let base_type = elements.first().copied()?;
            for metadata in elements.iter().skip(1) {
                self.visit_dependency_marker(metadata, Some(base_type), path_aliases);
            }
            return Some(base_type);
        }
        if matches!(expression, Expr::Call(_)) {
            self.unresolved = true;
        }
        Some(expression)
    }

    /// `FastAPI` reads `Depends`/`Security`/`Path` markers from both
    /// parameter defaults and `Annotated[...]` metadata; both contexts
    /// share this handling. Any other call shape — `Query()`, factory
    /// calls — or an unresolvable name bails out.
    fn visit_dependency_marker(
        &mut self,
        expression: &'a Expr,
        parameter_type: Option<&'a Expr>,
        path_aliases: &mut Vec<String>,
    ) {
        let resolved = self.resolve_alias_chain(expression);
        match resolved {
            Expr::Call(call) => {
                if self.is_depends_call(call) {
                    self.visit_depends_call(call, parameter_type);
                } else if self.is_path_call(call) {
                    self.visit_path_alias(call, path_aliases);
                } else {
                    self.unresolved = true;
                }
            }
            Expr::Name(_) | Expr::Attribute(_) => self.unresolved = true,
            _ => {}
        }
    }

    /// `Depends(target)` inspects `target`'s signature; bare `Depends()`
    /// falls back to the parameter's declared type, and `Depends()` with
    /// no type at all gives `FastAPI` nothing to inspect.
    fn visit_depends_call(&mut self, call: &'a ExprCall, parameter_type: Option<&'a Expr>) {
        let explicit = nth_or_keyword_argument(call, 0, "dependency");
        let Some(target) = explicit.or(parameter_type) else {
            return;
        };
        self.visit_dependency_callable(target);
    }

    /// `Path(alias="...")` renames the parameter for path matching; an
    /// unresolvable alias value bails out.
    fn visit_path_alias(&mut self, call: &'a ExprCall, path_aliases: &mut Vec<String>) {
        let Some(alias_argument) = keyword_argument(call, "alias") else {
            return;
        };
        match extract_string_value(self.facts, alias_argument) {
            Some(alias) => path_aliases.push(alias),
            None => self.unresolved = true,
        }
    }

    /// Inspects a dependency callable: same-file functions and methods
    /// contribute their parameters, classes contribute their `__init__`
    /// (or `__call__` for instances), lambdas their parameters, and
    /// anything unresolvable or unsupported bails out.
    fn visit_dependency_callable(&mut self, expression: &'a Expr) {
        let target = self.resolve_alias_chain(expression);
        if let Some(function) = self.dependency_function(target) {
            self.visit_function(function, false, false);
            return;
        }
        if let Some(class) = self.dependency_class(target) {
            self.visit_class_constructor(class);
            return;
        }
        if let Expr::Call(call) = target {
            // `Depends(ItemChecker())` / `checker = ItemChecker();
            // Depends(checker)`: FastAPI inspects the instance `__call__`.
            let callee = self.resolve_alias_chain(&call.func);
            if let Some(class) = self.dependency_class(callee) {
                self.visit_callable_instance(class);
                return;
            }
        }
        if let Expr::Lambda(lambda) = target {
            self.visit_lambda(lambda);
            return;
        }
        self.unresolved = true;
    }

    /// `Depends(Class)` inspects the constructor; classes with decorators
    /// or base classes may generate or inherit constructor parameters, so
    /// they bail out when no `__init__` is defined.
    fn visit_class_constructor(&mut self, class: &'a StmtClassDef) {
        if let Some(init) = self.facts.top_level_method(class, "__init__") {
            self.visit_function(init, true, false);
        } else if !class.decorator_list.is_empty() || class.arguments.is_some() {
            self.unresolved = true;
        }
    }

    /// `Depends(instance)` inspects `__call__`; decorated or inheriting
    /// classes may acquire callable behavior, so they bail out.
    fn visit_callable_instance(&mut self, class: &'a StmtClassDef) {
        if let Some(call) = self.facts.top_level_method(class, "__call__") {
            self.visit_function(call, true, false);
        } else if !class.decorator_list.is_empty() || class.arguments.is_some() {
            self.unresolved = true;
        }
    }

    /// Resolves `expr` to a same-file function definition: a bare name
    /// through the scope chain, `Class.method`/`self.method` to a
    /// top-level method of the resolved or enclosing class.
    fn dependency_function(&self, expr: &'a Expr) -> Option<&'a StmtFunctionDef> {
        match expr {
            Expr::Name(_) => self.facts.resolve_function_def(expr, expr.range()),
            Expr::Attribute(attribute) => {
                let owner = self.resolve_alias_chain(&attribute.value);
                let class = match owner {
                    Expr::Name(name) if name.id.as_str() == "self" || name.id.as_str() == "cls" => {
                        self.facts.enclosing_class(expr.range())
                    }
                    _ => self.facts.resolve_class_def(owner, expr.range()),
                }?;
                self.facts.top_level_method(class, attribute.attr.as_str())
            }
            _ => None,
        }
    }

    /// Resolves `expr` to a same-file class definition.
    fn dependency_class(&self, expr: &'a Expr) -> Option<&'a StmtClassDef> {
        match expr {
            Expr::Name(_) | Expr::Attribute(_) => self.facts.resolve_class_def(expr, expr.range()),
            _ => None,
        }
    }

    /// Follows `name = value` alias chains using Sonar's strict
    /// `singleAssignedValue` shape (plain `name = value` only), returning
    /// the expression at which resolution stalls.
    fn resolve_alias_chain<'b>(&self, mut expr: &'b Expr) -> &'b Expr
    where
        'a: 'b,
    {
        let mut visited: HashSet<TextRange> = HashSet::new();
        while let Expr::Name(name) = expr {
            let Some((value, _)) = self
                .facts
                .strict_single_assignment(name.id.as_str(), name.range())
            else {
                break;
            };
            if !visited.insert(value.range()) {
                break;
            }
            expr = value;
        }
        expr
    }

    /// The dotted spelling of the alias-resolved expression — Sonar's
    /// `localAliasResolvedName` fallback for names whose FQN is unknown.
    fn local_alias_resolved_name(&self, expr: &Expr) -> Option<String> {
        lexical_dotted_name(self.resolve_alias_chain(expr))
    }

    fn is_annotated_object(&self, expr: &Expr) -> bool {
        if self
            .facts
            .expr_fqn(expr)
            .is_some_and(|fqn| ANNOTATED_FQNS.contains(&fqn.as_str()))
        {
            return true;
        }
        self.local_alias_resolved_name(expr)
            .is_some_and(|name| ANNOTATED_FQNS.contains(&name.as_str()))
    }

    fn is_depends_call(&self, call: &ExprCall) -> bool {
        if self
            .facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| DEPENDS_FQNS.contains(&fqn.as_str()))
        {
            return true;
        }
        self.local_alias_resolved_name(&call.func)
            .is_some_and(|name| name == "Depends" || name == "Security")
    }

    fn is_path_call(&self, call: &ExprCall) -> bool {
        if self
            .facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| PATH_FQNS.contains(&fqn.as_str()))
        {
            return true;
        }
        self.local_alias_resolved_name(&call.func)
            .is_some_and(|name| name == "Path")
    }

    fn is_app_or_router_call(&self, call: &ExprCall) -> bool {
        if self
            .facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| APP_OR_ROUTER_FQNS.contains(&fqn.as_str()))
        {
            return true;
        }
        self.local_alias_resolved_name(&call.func)
            .is_some_and(|name| APP_OR_ROUTER_NAMES.contains(&name.as_str()))
    }
}

/// One entry of Sonar's `ParameterList.nonTuple()`: a named parameter or
/// a `*args`/`**kwargs` variadic (ruff folds the `/`/`*` separators into
/// the parameter lists, so only named and variadic entries appear).
struct ParamEntry<'a> {
    parameter: &'a ruff_python_ast::Parameter,
    default: Option<&'a Expr>,
    /// `"*"` for `*args`, `"**"` for `**kwargs`, `None` otherwise.
    star: Option<&'static str>,
    positional_only: bool,
}

/// All parameters in declaration order: positional-only, regular,
/// `*args`, keyword-only, `**kwargs`.
fn parameter_entries(parameters: &Parameters) -> Vec<ParamEntry<'_>> {
    let mut entries = Vec::with_capacity(parameters.len());
    for param in &parameters.posonlyargs {
        entries.push(ParamEntry {
            parameter: &param.parameter,
            default: param.default(),
            star: None,
            positional_only: true,
        });
    }
    for param in &parameters.args {
        entries.push(ParamEntry {
            parameter: &param.parameter,
            default: param.default(),
            star: None,
            positional_only: false,
        });
    }
    if let Some(vararg) = &parameters.vararg {
        entries.push(ParamEntry {
            parameter: vararg,
            default: None,
            star: Some("*"),
            positional_only: false,
        });
    }
    for param in &parameters.kwonlyargs {
        entries.push(ParamEntry {
            parameter: &param.parameter,
            default: param.default(),
            star: None,
            positional_only: false,
        });
    }
    if let Some(kwarg) = &parameters.kwarg {
        entries.push(ParamEntry {
            parameter: kwarg,
            default: None,
            star: Some("**"),
            positional_only: false,
        });
    }
    entries
}

/// `{name}` and `{name:converter}` path parameters of the route path, in
/// first-appearance order. Sonar's pattern is `\{([a-zA-Z_]\w*)(?::[a-zA-Z_]\w*)?\}`.
fn extract_path_parameters(facts: &WebFrameworkFacts<'_>, call: &ExprCall) -> BTreeSet<String> {
    let mut params = BTreeSet::new();
    let Some(path) =
        nth_or_keyword_argument(call, 0, "path").and_then(|expr| extract_string_value(facts, expr))
    else {
        return params;
    };
    let bytes = path.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'{'
            && let Some((name, end)) = parse_path_param(&path, index)
        {
            params.insert(name);
            index = end;
        } else {
            index += 1;
        }
    }
    params
}

/// Parses `{name}` or `{name:conv}` starting at `open` (the `{` index),
/// returning the parameter name and the index just past `}`.
fn parse_path_param(path: &str, open: usize) -> Option<(String, usize)> {
    let bytes = path.as_bytes();
    let mut index = open + 1;
    let name_start = index;
    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        index += 1;
    }
    if index == name_start || bytes[name_start].is_ascii_digit() {
        return None;
    }
    let name = &path[name_start..index];
    if index < bytes.len() && bytes[index] == b':' {
        index += 1;
        let converter_start = index;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        if index == converter_start || bytes[converter_start].is_ascii_digit() {
            return None;
        }
    }
    if index < bytes.len() && bytes[index] == b'}' {
        Some((name.to_string(), index + 1))
    } else {
        None
    }
}

/// The string value of a literal or of a name bound once to a string
/// literal — Sonar's `Expressions.extractStringLiteral`. Implicit
/// concatenation joins the parts; f-strings and other expressions yield
/// `None`.
fn extract_string_value(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(literal) => Some(literal.value.to_str().to_string()),
        Expr::Name(name) => {
            let (value, _) = facts.strict_single_assignment(name.id.as_str(), name.range())?;
            match value {
                Expr::StringLiteral(literal) => Some(literal.value.to_str().to_string()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The dotted spelling of a pure name/attribute chain (`t.Annotated`).
fn lexical_dotted_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(name) => Some(name.id.to_string()),
        Expr::Attribute(attribute) => Some(format!(
            "{}.{}",
            lexical_dotted_name(&attribute.value)?,
            attribute.attr.as_str()
        )),
        _ => None,
    }
}

/// Elements of a subscript slice: `X[a]` → `[a]`, `X[a, b]` → `[a, b]`.
fn subscript_elements(slice: &Expr) -> Vec<&Expr> {
    match slice {
        Expr::Tuple(tuple) => tuple.elts.iter().collect(),
        expr => vec![expr],
    }
}

/// Reports each undeclared path parameter (suppressed when any parameter
/// source was unresolved or unsupported) and each positional-only path
/// parameter on the function name.
fn report_issues(
    collector: &DependencyCollector<'_, '_>,
    function: &StmtFunctionDef,
    path_params: &BTreeSet<String>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for param in path_params {
        if !collector.names.contains(param) && !collector.unresolved {
            issues.push(issue_at(
                RULE_KEY,
                &format!("Add path parameter \"{param}\" to the function signature."),
                function.name.range(),
                index,
                source,
            ));
        }
    }
    for param in path_params {
        if collector.positional_only.contains(param) {
            issues.push(issue_at(
                RULE_KEY,
                &format!("Path parameter \"{param}\" should not be positional-only."),
                function.name.range(),
                index,
                source,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8411")
            .into_iter()
            .cloned()
            .collect()
    }

    const PRELUDE: &str = concat!(
        "import typing\n",
        "from fastapi import FastAPI, APIRouter, Depends, Security, Path\n",
        "from typing import Annotated\n",
        "from pydantic import BaseModel\n",
        "from dataclasses import dataclass\n",
        "import typing_extensions\n",
        "\n",
        "app = FastAPI()\n",
        "router = APIRouter()\n",
        "\n",
    );

    #[test]
    fn s8411_flags_undeclared_path_parameters() {
        // Sonar's Noncompliant examples: missing path parameters on every
        // verb, converters, `path=` keyword, and dynamic path constants.
        let issues = found(
            &[
                PRELUDE,
                concat!(
                    "@app.get(\"/items/{item_id}\")\n",
                    "def noncompliant_missing_path_param():\n",
                    "    return {\"message\": \"Hello\"}\n",
                    "\n",
                    "@app.get(\"/users/{user_id}/items/{item_id}\")\n",
                    "def noncompliant_missing_one_of_multiple_params(user_id: int):\n",
                    "    return {\"user_id\": user_id}\n",
                    "\n",
                    "@router.put(\"/items/{item_id}\")\n",
                    "def noncompliant_router_missing_param():\n",
                    "    return {\"updated\": True}\n",
                    "\n",
                    "@app.post(\"/items/{item_id}\")\n",
                    "def noncompliant_post_missing():\n",
                    "    pass\n",
                    "\n",
                    "@app.delete(\"/items/{item_id}\")\n",
                    "def noncompliant_delete_missing():\n",
                    "    pass\n",
                    "\n",
                    "@app.patch(\"/items/{item_id}\")\n",
                    "def noncompliant_patch_missing():\n",
                    "    pass\n",
                    "\n",
                    "@app.options(\"/items/{item_id}\")\n",
                    "def noncompliant_options_missing():\n",
                    "    pass\n",
                    "\n",
                    "@app.head(\"/items/{item_id}\")\n",
                    "def noncompliant_head_missing():\n",
                    "    pass\n",
                    "\n",
                    "@app.trace(\"/items/{item_id}\")\n",
                    "def noncompliant_trace_missing():\n",
                    "    pass\n",
                    "\n",
                    "@app.get(\"/items/{item_id:int}\")\n",
                    "def noncompliant_with_converter_missing():\n",
                    "    pass\n",
                    "\n",
                    "@app.get(\"/a/{x}/b/{y}/c/{z}\")\n",
                    "def noncompliant_all_params_missing():\n",
                    "    pass\n",
                    "\n",
                    "@app.get(path=\"/items/{item_id}\")\n",
                    "def noncompliant_path_keyword_missing():\n",
                    "    return {}\n",
                    "\n",
                    "path = \"/items/{item_id}\"\n",
                    "@app.get(path)\n",
                    "def noncompliant_dynamic_path():\n",
                    "    pass\n",
                    "\n",
                    "@app.get(\"/items/{item_id}\")\n",
                    "def noncompliant_star_args_only(*args):\n",
                    "    return args\n",
                ),
            ]
            .concat(),
        );
        // 13 single-parameter findings + 3 for {x}/{y}/{z}.
        assert_eq!(issues.len(), 16);
        assert_eq!(
            issues[0].message,
            "Add path parameter \"item_id\" to the function signature."
        );
        // The issue anchors the function name `noncompliant_missing_path_param`.
        assert_eq!(issues[0].range.start, pos(12, 4));
        assert_eq!(issues[0].range.end, pos(12, 35));
    }

    #[test]
    fn s8411_flags_positional_only_path_parameters() {
        let issues = found(
            &[
                PRELUDE,
                concat!(
                    "@app.get(\"/items/{item_id}\")\n",
                    "def noncompliant_positional_only_param(item_id: int, /):\n",
                    "    return {\"item_id\": item_id}\n",
                    "\n",
                    "@app.get(\"/users/{user_id}/posts/{post_id}\")\n",
                    "def noncompliant_multiple_positional_only(user_id: int, post_id: int, /):\n",
                    "    pass\n",
                    "\n",
                    "@app.get(\"/users/{user_id}/items/{item_id}\")\n",
                    "def noncompliant_mixed_positional_only_and_missing(user_id: int, /):\n",
                    "    pass\n",
                ),
            ]
            .concat(),
        );
        assert_eq!(issues.len(), 5);
        assert_eq!(
            issues[0].message,
            "Path parameter \"item_id\" should not be positional-only."
        );
        // Mixed case: positional-only user_id plus missing item_id.
        let messages: Vec<&str> = issues.iter().map(|issue| issue.message.as_str()).collect();
        assert!(messages.contains(&"Path parameter \"user_id\" should not be positional-only."));
        assert!(messages.contains(&"Add path parameter \"item_id\" to the function signature."));
    }

    #[test]
    fn s8411_accepts_declared_path_parameters() {
        assert!(
            found(
                &[
                    PRELUDE,
                    concat!(
                        "@app.get(\"/items/{item_id}\")\n",
                        "def compliant_basic(item_id: int):\n",
                        "    return {\"item_id\": item_id}\n",
                        "\n",
                        "@app.get(\"/users/{user_id}/items/{item_id}\")\n",
                        "def compliant_reordered_params(item_id: int, user_id: int):\n",
                        "    return {\"user_id\": user_id, \"item_id\": item_id}\n",
                        "\n",
                        "@app.get(\"/things/{thing_id}\")\n",
                        "async def compliant_async_with_query(thing_id: int, query: str):\n",
                        "    return {\"thing_id\": thing_id, \"query\": query}\n",
                        "\n",
                        "@app.get(\"/items\")\n",
                        "def compliant_static_route():\n",
                        "    return {\"items\": []}\n",
                        "\n",
                        "@app.get(\"/items/{item_id}\")\n",
                        "def compliant_keyword_only(*, item_id: int):\n",
                        "    return {\"item_id\": item_id}\n",
                        "\n",
                        "@app.get(\"/items/{item_id}\")\n",
                        "def compliant_with_default(item_id: int = 1):\n",
                        "    return {\"item_id\": item_id}\n",
                        "\n",
                        "@app.get(\"/items/{item_id:int}\")\n",
                        "def compliant_with_converter(item_id: int):\n",
                        "    return {\"item_id\": item_id}\n",
                        "\n",
                        "@app.get(status_code=200, path=\"/items/{item_id}\")\n",
                        "def compliant_path_keyword(item_id: int):\n",
                        "    return {\"item_id\": item_id}\n",
                        "\n",
                        "def some_other_decorator(path):\n",
                        "    def wrapper(func):\n",
                        "        return func\n",
                        "    return wrapper\n",
                        "\n",
                        "@some_other_decorator(\"/items/{item_id}\")\n",
                        "def compliant_not_fastapi_decorator():\n",
                        "    pass\n",
                        "\n",
                        "@app.get\n",
                        "def compliant_decorator_without_call():\n",
                        "    pass\n",
                        "\n",
                        "@app.get(\"\")\n",
                        "def compliant_empty_path():\n",
                        "    pass\n",
                        "\n",
                        "@app.get(True)\n",
                        "def compliant_path_is_not_a_string():\n",
                        "    pass\n",
                        "\n",
                        "piece = \"item_id\"\n",
                        "@app.get(f\"/items/{piece}/details\")\n",
                        "def compliant_fstring_path():\n",
                        "    pass\n",
                        "\n",
                        "@app.get(\"/items/\" f\"{piece}\" \"/details\")\n",
                        "def compliant_combined_fstring_path():\n",
                        "    pass\n",
                        "\n",
                        "@app.get(f\"/items/{{item_id}}/details\")\n",
                        "def known_fn_escaped_fstring_path():\n",
                        "    pass\n",
                        "\n",
                        "@app.get(\"/items/{item_id : path}\")\n",
                        "def compliant_ignore_invalid_starlette_route_0():\n",
                        "    pass\n",
                        "\n",
                        "@app.get(\"/items/{ item_id }\")\n",
                        "def compliant_ignore_invalid_starlette_route_1():\n",
                        "    pass\n",
                    )
                ]
                .concat()
            )
            .is_empty()
        );
    }

    #[test]
    fn s8411_bails_out_on_kwargs_and_unresolved_sources() {
        assert!(
            found(
                &[
                    PRELUDE,
                    concat!(
                        "@app.get(\"/items/{item_id}\")\n",
                        "def no_issue_bailout_with_kwargs(**kwargs):\n",
                        "    return kwargs\n",
                        "\n",
                        "@app.get(\"/items/{item_id}\")\n",
                        "def no_issue_bailout_with_args_kwargs(*args, **kwargs):\n",
                        "    return {\"args\": args, \"kwargs\": kwargs}\n",
                        "\n",
                        "@app.get(\"/items/{item_id}\")\n",
                        "def no_issue_bailout_query_default(q: str = Query(None)):\n",
                        "    return {\"q\": q}\n",
                        "\n",
                        "@app.get(\"/items/{item_id}\")\n",
                        "def no_issue_bailout_name_default(q=default_query):\n",
                        "    return {\"q\": q}\n",
                    )
                ]
                .concat()
            )
            .is_empty()
        );
    }

    #[test]
    fn s8411_follows_depends_dependencies() {
        let issues = found(&[PRELUDE, concat!(
            "def get_item(item_id: int):\n",
            "    return {\"item_id\": item_id}\n",
            "\n",
            "def get_item_positional_only(item_id: int, /):\n",
            "    return {\"item_id\": item_id}\n",
            "\n",
            "def dep_without_item_id(name: str):\n",
            "    return name\n",
            "\n",
            "def get_item_wrapper(item=Depends(get_item)):\n",
            "    return item\n",
            "\n",
            "def dep_b_circular(dep=Depends(dep_a_circular)):\n",
            "    return dep\n",
            "\n",
            "def dep_a_circular(item_id: int, dep=Depends(dep_b_circular)):\n",
            "    return item_id\n",
            "\n",
            "class ItemDepsHolder:\n",
            "    @staticmethod\n",
            "    def get_item(item_id: int):\n",
            "        return item_id\n",
            "\n",
            "@router.get(\"/items/{item_id}\")\n",
            "def compliant_depends_default_value(item=Depends(get_item)):\n",
            "    return item\n",
            "\n",
            "@router.get(\"/items/{item_id}\")\n",
            "def compliant_depends_positional_only_dependency(item=Depends(get_item_positional_only)):\n",
            "    return item\n",
            "\n",
            "@router.get(\"/items/{item_id}\")\n",
            "def compliant_depends_dependency_keyword(item=Depends(dependency=get_item)):\n",
            "    return item\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_depends_annotated(item: Annotated[dict, Depends(get_item)]):\n",
            "    return item\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_depends_annotated_qualified(item: typing.Annotated[dict, Depends(get_item)]):\n",
            "    return item\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_depends_annotated_from_typing_extension(item: typing_extensions.Annotated[dict, Depends(get_item)]):\n",
            "    return item\n",
            "\n",
            "@app.get(\"/users/{user_id}/items/{item_id}\")\n",
            "def compliant_depends_partial(user_id: int, item=Depends(get_item)):\n",
            "    return {\"user_id\": user_id, \"item\": item}\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_security_dependency(item=Security(get_item)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_multiple_depends_metadata_union(item: Annotated[dict, Depends(dep_without_item_id), Depends(get_item)]):\n",
            "    pass\n",
            "\n",
            "@router.get(\"/items/{item_id}\")\n",
            "def compliant_nested_depends(item=Depends(get_item_wrapper)):\n",
            "    return item\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_circular_depends(dep=Depends(dep_a_circular)):\n",
            "    return dep\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_qualified_expr_depends(dep=Depends(ItemDepsHolder.get_item)):\n",
            "    return dep\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_lambda_depends_with_path_param(dep=Depends(lambda item_id: item_id)):\n",
            "    return dep\n",
        )].concat());
        assert!(issues.is_empty());
    }

    #[test]
    fn s8411_flags_uncovered_dependencies() {
        let issues = found(&[PRELUDE, concat!(
            "def dep_without_item_id(name: str):\n",
            "    return name\n",
            "\n",
            "def dep_level2_no_id(name: str):\n",
            "    return name\n",
            "\n",
            "def dep_level1_no_id(x=Depends(dep_level2_no_id)):\n",
            "    return x\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_depends_param_not_in_dep(item=Depends(dep_without_item_id)):\n",
            "    return item\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_multiple_depends_metadata_no_match(item: Annotated[dict, Depends(dep_without_item_id), Depends(dep_without_item_id)]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_nested_depends_not_covering(item=Depends(dep_level1_no_id)):\n",
            "    return item\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_lambda_depends(dep=Depends(lambda: None)):\n",
            "    return dep\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_depends_without_target(dep=Depends()):\n",
            "    pass\n",
        )].concat());
        assert_eq!(issues.len(), 5);
        assert!(issues.iter().all(|issue| issue.message.contains("item_id")));
    }

    #[test]
    fn s8411_bails_out_on_unresolvable_dependencies() {
        let issues = found(&[PRELUDE, concat!(
            "def dependency_factory():\n",
            "    return dep_without_item_id\n",
            "\n",
            "def dependency_marker_factory():\n",
            "    return Depends(get_item)\n",
            "\n",
            "def wrapper(dep=Depends(unknown_dependency)):\n",
            "    return dep\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def no_issue_bailout_unresolved_dependency(item=Depends(unknown_dependency)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def no_issue_bailout_dynamic_dependency(item=Depends(dependency_factory())):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def no_issue_bailout_dynamic_default_value_dependency(item=dependency_marker_factory()):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def no_issue_bailout_unknown_nested_dependency(item=Depends(wrapper)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/users/{user_id}/items/{item_id}\")\n",
            "def noncompliant_positional_only_and_missing_bailout(user_id: int, /, item=Depends(unknown_dependency)):\n",
            "    pass\n",
        )].concat());
        // Only the positional-only finding survives the bailout.
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Path parameter \"user_id\" should not be positional-only."
        );
    }

    #[test]
    fn s8411_follows_route_and_constructor_dependency_lists() {
        let issues = found(&[PRELUDE, concat!(
            "def get_item(item_id: int):\n",
            "    return {\"item_id\": item_id}\n",
            "\n",
            "def dep_without_item_id(name: str):\n",
            "    return name\n",
            "\n",
            "router_with_dependency = APIRouter(dependencies=[Depends(get_item)])\n",
            "router_without_path_dependency = APIRouter(dependencies=[Depends(dep_without_item_id)])\n",
            "app_with_dependency = FastAPI(dependencies=[Depends(get_item)])\n",
            "FastAPIAlias = FastAPI\n",
            "app_with_aliased_fastapi_dependency = FastAPIAlias(dependencies=[Depends(get_item)])\n",
            "\n",
            "@app.get(\"/items/{item_id}\", dependencies=[Depends(get_item)])\n",
            "def compliant_route_dependency_covers_path_param():\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\", dependencies=[Depends(dep_without_item_id)])\n",
            "def noncompliant_route_dependency_does_not_cover_path_param():\n",
            "    pass\n",
            "\n",
            "@router_with_dependency.get(\"/items/{item_id}\")\n",
            "def compliant_router_dependency_covers_path_param():\n",
            "    pass\n",
            "\n",
            "@router_without_path_dependency.get(\"/items/{item_id}\")\n",
            "def noncompliant_router_dependency_does_not_cover_path_param():\n",
            "    pass\n",
            "\n",
            "@app_with_dependency.get(\"/items/{item_id}\")\n",
            "def compliant_app_dependency_covers_path_param():\n",
            "    pass\n",
            "\n",
            "@app_with_aliased_fastapi_dependency.get(\"/items/{item_id}\")\n",
            "def compliant_aliased_app_dependency_covers_path_param():\n",
            "    pass\n",
        )].concat());
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn s8411_bails_out_on_dynamic_dependency_lists() {
        assert!(
            found(&[PRELUDE, concat!(
                "def get_route_dependencies():\n",
                "    return []\n",
                "\n",
                "def dependency_marker_factory():\n",
                "    return Depends(get_item)\n",
                "\n",
                "dependencies = [Depends(unknown_dependency)]\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=dependencies)\n",
                "def no_issue_bailout_route_dependencies_alias_with_unresolved_dependency():\n",
                "    pass\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=unknown_dependencies)\n",
                "def no_issue_bailout_unresolved_route_dependencies_argument():\n",
                "    pass\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=get_route_dependencies())\n",
                "def no_issue_bailout_dynamic_route_dependencies_argument():\n",
                "    pass\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=[dependency_marker_factory()])\n",
                "def no_issue_bailout_dynamic_route_dependency_list_entry():\n",
                "    pass\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=[Depends(unknown_dependency)])\n",
                "def no_issue_bailout_dependency_unresolved():\n",
                "    pass\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=[unknown_dependency])\n",
                "def no_issue_bailout_unresolved_direct_route_dependency():\n",
                "    pass\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=[*dependencies])\n",
                "def no_issue_bailout_on_dependencies_sequence_unpacking():\n",
                "    pass\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=[object()])\n",
                "def no_issue_bailout_invalid_route_dependency_list_entry_object():\n",
                "    pass\n",
                "\n",
                "@app.get(\"/items/{item_id}\", dependencies=[42])\n",
                "def no_issue_bailout_invalid_route_dependency_list_entry_integer():\n",
                "    pass\n",
            )].concat())
            .is_empty()
        );
    }

    #[test]
    fn s8411_honors_path_aliases() {
        let issues = found(&[PRELUDE, concat!(
            "ITEM_ID_ALIAS = \"item-id\"\n",
            "\n",
            "def get_item_with_alias(item_id: Annotated[int, Path(alias=\"item-id\")]):\n",
            "    return item_id\n",
            "\n",
            "def get_item_with_default_alias(item_id: int = Path(alias=\"item-id\")):\n",
            "    return item_id\n",
            "\n",
            "@app.get(\"/items/{item-id}\")\n",
            "def compliant_literal_path_alias(item_id: Annotated[int, Path(alias=\"item-id\")]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_path_alias_replaces_parameter_name(item_id: Annotated[int, Path(alias=\"other_id\")]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item-id}\")\n",
            "def compliant_default_value_path_alias(item_id: int = Path(alias=\"item-id\")):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_default_value_path_without_alias(item_id: int = Path()):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_default_value_path_without_alias(other_id: int = Path()):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item-id}\")\n",
            "def compliant_constant_path_alias(item_id: Annotated[int, Path(alias=ITEM_ID_ALIAS)]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item-id}\")\n",
            "def no_issue_bailout_unknown_path_alias(item_id: Annotated[int, Path(alias=get_alias_unresolved())]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item-id}\")\n",
            "def no_issue_bailout_unknown_default_value_path_alias(item_id: int = Path(alias=get_alias_unresolved())):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item-id}\")\n",
            "def compliant_dependency_has_path_alias(item=Depends(get_item_with_alias)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item-id}\")\n",
            "def compliant_dependency_default_value_path_alias(item=Depends(get_item_with_default_alias)):\n",
            "    pass\n",
        )].concat());
        // `{item-id}` never matches the path pattern, so only the two
        // `{item_id}` routes with mismatched/missing parameters report.
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().all(|issue| issue.message.contains("item_id")));
    }

    #[test]
    fn s8411_follows_class_dependencies() {
        let issues = found(&[PRELUDE, concat!(
            "class ItemQuery:\n",
            "    def __init__(self, item_id: int):\n",
            "        pass\n",
            "\n",
            "class EmptyItemQuery:\n",
            "    pass\n",
            "\n",
            "class PydanticItemQueryWithoutPathParam(BaseModel):\n",
            "    name: str\n",
            "\n",
            "@dataclass\n",
            "class DataclassItemQueryWithoutPathParam:\n",
            "    name: str\n",
            "\n",
            "def generated_constructor(cls):\n",
            "    return cls\n",
            "\n",
            "@generated_constructor\n",
            "class DecoratedItemQuery:\n",
            "    item_id: int\n",
            "\n",
            "class ItemChecker:\n",
            "    def __call__(self, item_id: int):\n",
            "        return item_id\n",
            "\n",
            "checker = ItemChecker()\n",
            "\n",
            "class DependencyWithoutCall:\n",
            "    pass\n",
            "\n",
            "dependency_without_call = DependencyWithoutCall()\n",
            "\n",
            "class InheritedCallableDependency(ItemChecker):\n",
            "    pass\n",
            "\n",
            "inherited_callable_dependency = InheritedCallableDependency()\n",
            "\n",
            "class ItemCheckerClassReference:\n",
            "    def __call__(self, item_id: int):\n",
            "        return item_id\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_class_dependency(query: Annotated[ItemQuery, Depends(ItemQuery)]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_class_dependency_default_value(query: ItemQuery = Depends(ItemQuery)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_class_dependency_without_path_param_in_init(query: Annotated[EmptyItemQuery, Depends(EmptyItemQuery)]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def no_issue_bailout_pydantic_dependency(query: Annotated[PydanticItemQueryWithoutPathParam, Depends(PydanticItemQueryWithoutPathParam)]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def no_issue_bailout_dataclass_dependency(query: Annotated[DataclassItemQueryWithoutPathParam, Depends(DataclassItemQueryWithoutPathParam)]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def no_issue_bailout_decorated_class_without_explicit_init(query: Annotated[DecoratedItemQuery, Depends(DecoratedItemQuery)]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_callable_instance_dependency(item=Depends(checker)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_callable_constructor_instance_dependency(item=Depends(ItemChecker())):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_dependency_instance_without_call(item=Depends(dependency_without_call)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{other_id}\")\n",
            "def no_issue_bailout_inherited_callable_dependency(item=Depends(inherited_callable_dependency)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def noncompliant_class_dependency_without_init_path_param(item=Depends(ItemCheckerClassReference)):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_depends_shortcut_annotated(query: Annotated[ItemQuery, Depends()]):\n",
            "    pass\n",
            "\n",
            "@app.get(\"/items/{item_id}\")\n",
            "def compliant_depends_shortcut_default(query: ItemQuery = Depends()):\n",
            "    pass\n",
        )].concat());
        assert_eq!(issues.len(), 3);
        assert!(issues.iter().all(|issue| issue.message.contains("item_id")));
    }

    #[test]
    fn s8411_resolves_type_alias_annotations() {
        let issues = found(
            &[
                PRELUDE,
                concat!(
                    "def get_item(item_id: int):\n",
                    "    return {\"item_id\": item_id}\n",
                    "\n",
                    "ItemDependency = Annotated[dict, Depends(get_item)]\n",
                    "\n",
                    "def get_dependency_annotation():\n",
                    "    return Annotated[dict, Depends(dep_without_item_id)]\n",
                    "\n",
                    "DynamicDependency = get_dependency_annotation()\n",
                    "\n",
                    "CyclicDependencyA = CyclicDependencyB\n",
                    "CyclicDependencyB = CyclicDependencyA\n",
                    "\n",
                    "@app.get(\"/items/{item_id}\")\n",
                    "def compliant_depends_annotated_type_alias(item: ItemDependency):\n",
                    "    pass\n",
                    "\n",
                    "@app.get(\"/items/{item_id}\")\n",
                    "def no_issue_bailout_runtime_type_alias(item: DynamicDependency):\n",
                    "    pass\n",
                    "\n",
                    "@app.get(\"/items/{item_id}\")\n",
                    "def no_issue_bailout_cyclic_type_alias(item: CyclicDependencyA):\n",
                    "    pass\n",
                ),
            ]
            .concat(),
        );
        assert!(issues.is_empty());
    }
}
