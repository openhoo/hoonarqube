use crate::AnalyzerOptions;
use crate::engine::scope::{BindingKind, DefFlavor, ScopeKind, SymbolTable, build_symbol_table};
use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::to_u32;
use crate::support::{child_bodies, for_each_stmt_expr};
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::{Expr, ExprContext, ExprName, Stmt, StmtClassDef, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use std::collections::{HashMap, HashSet};

/// python:S107 — parameter count against `maximumFunctionParameters`;
/// `*args` and `**kwargs` each count as one parameter.
pub(crate) fn check_function_parameter_counts(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut parent_signatures = None;
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, in_class_body| {
            let parameters = &function.parameters;
            let mut count = parameters.posonlyargs.len()
                + parameters.args.len()
                + parameters.kwonlyargs.len()
                + usize::from(parameters.vararg.is_some())
                + usize::from(parameters.kwarg.is_some());
            // The receiver is implicitly passed, so methods (except
            // staticmethods) count one parameter fewer.
            let is_method =
                in_class_body && !crate::support::has_decorator(function, "staticmethod");
            if is_method {
                count = count.saturating_sub(1);
            }
            let maximum = options.maximum_function_parameters;
            if to_u32(count) > maximum {
                if in_class_body
                    && parent_signatures
                        .get_or_insert_with(|| ParentSignatures::build(parsed))
                        .suppresses(function, maximum)
                {
                    return;
                }
                let kind = if is_method { "Method" } else { "Function" };
                issues.push(issue_at(
                    "python:S107",
                    &format!(
                        "{kind} \"{}\" has {count} parameters, which is greater than the \
                         {maximum} authorized.",
                        function.name
                    ),
                    parameter_list_range(parsed, &function.parameters),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}

fn parameter_list_range(
    parsed: &Parsed<ModModule>,
    parameters: &ruff_python_ast::Parameters,
) -> ruff_text_size::TextRange {
    let first = parameters
        .iter_source_order()
        .next()
        .expect("nonempty parameters");
    let last = parameters
        .iter_source_order()
        .last()
        .expect("nonempty parameters");
    // Ruff omits the bare keyword-only separator from formal parameters;
    // the reference parameter-list node includes it as its first child.
    let start = if parameters.posonlyargs.is_empty()
        && parameters.args.is_empty()
        && parameters.vararg.is_none()
        && !parameters.kwonlyargs.is_empty()
    {
        parsed
            .tokens()
            .iter()
            .find(|token| {
                token.kind() == ruff_python_ast::token::TokenKind::Star
                    && token.start() >= parameters.start()
                    && token.end() <= first.start()
            })
            .map_or(first.start(), Ranged::start)
    } else {
        first.start()
    };
    // The reference parameter-list node retains a trailing comma, while
    // ignoring trivia between it and the closing parenthesis.
    let end = parsed
        .tokens()
        .iter()
        .find(|token| {
            token.kind() == ruff_python_ast::token::TokenKind::Comma
                && token.start() >= last.end()
                && token.end() < parameters.end()
        })
        .map_or(last.end(), Ranged::end);
    ruff_text_size::TextRange::new(start, end)
}

#[derive(Clone, Copy)]
enum ParameterParent {
    Local(usize, bool),
    Object,
    Unresolved,
}

/// S107-only same-file parent signatures, indexed by existing lexical scope
/// identities. This does not infer external types or follow assigned aliases.
struct ParentSignatures<'a> {
    table: SymbolTable,
    classes: HashMap<usize, &'a StmtClassDef>,
    class_sites: HashMap<usize, usize>,
    functions: HashMap<TextRange, &'a StmtFunctionDef>,
    function_sites: HashMap<TextRange, usize>,
    loads: HashMap<TextRange, usize>,
    class_names: HashMap<TextRange, usize>,
    parents: HashMap<usize, Vec<ParameterParent>>,
    uncertain_definitions: HashSet<TextRange>,
    invalid_bindings: HashSet<(usize, String)>,
    dynamic: bool,
}

impl<'a> ParentSignatures<'a> {
    fn build(parsed: &'a Parsed<ModModule>) -> Self {
        let table = build_symbol_table(parsed);
        let mut class_nodes = HashMap::new();
        let mut functions = HashMap::new();
        let mut uncertain_definitions = HashSet::new();
        let mut dynamic = false;
        let mut pending: Vec<_> = parsed
            .syntax()
            .body
            .iter()
            .map(|stmt| (stmt, true))
            .collect();
        while let Some((stmt, unconditional)) = pending.pop() {
            match stmt {
                Stmt::ClassDef(class) => {
                    class_nodes.insert(class.name.range(), class);
                    if !unconditional
                        || !class.decorator_list.is_empty()
                        || class
                            .arguments
                            .as_deref()
                            .is_some_and(|args| !args.keywords.is_empty())
                    {
                        uncertain_definitions.insert(class.name.range());
                    }
                    pending.extend(class.body.iter().map(|stmt| (stmt, true)));
                }
                Stmt::FunctionDef(function) => {
                    functions.insert(function.name.range(), function);
                    if !unconditional {
                        uncertain_definitions.insert(function.name.range());
                    }
                    pending.extend(function.body.iter().map(|stmt| (stmt, true)));
                }
                Stmt::ImportFrom(import)
                    if import.names.iter().any(|alias| alias.name.as_str() == "*") =>
                {
                    dynamic = true;
                }
                _ => {
                    for body in child_bodies(stmt) {
                        pending.extend(body.iter().map(|stmt| (stmt, false)));
                    }
                }
            }
        }
        let mut facts = Self {
            loads: table
                .resolved_loads
                .iter()
                .filter_map(|load| load.target.map(|scope| (load.range, scope)))
                .collect(),
            table,
            classes: HashMap::new(),
            class_sites: HashMap::new(),
            functions,
            function_sites: HashMap::new(),
            class_names: HashMap::new(),
            parents: HashMap::new(),
            uncertain_definitions,
            invalid_bindings: HashSet::new(),
            dynamic,
        };
        facts.index_definition_sites(&class_nodes);
        facts.collect_uncertainty(parsed);
        for (&scope, class) in &facts.classes {
            let parents = facts.parents_for_class(class);
            facts.parents.insert(scope, parents);
        }
        facts
    }

    fn index_definition_sites(&mut self, class_nodes: &HashMap<TextRange, &'a StmtClassDef>) {
        for (index, site) in self.table.def_sites.iter().enumerate() {
            if site.flavor == DefFlavor::Class {
                if let Some(class) = class_nodes.get(&site.name_range) {
                    self.classes.insert(site.own_scope, *class);
                    self.class_sites.insert(site.own_scope, index);
                    self.class_names.insert(site.name_range, site.own_scope);
                }
            } else {
                self.function_sites.insert(site.name_range, index);
            }
        }
    }

    fn parents_for_class(&self, class: &StmtClassDef) -> Vec<ParameterParent> {
        class
            .arguments
            .as_deref()
            .map_or_else(Vec::new, |arguments| {
                arguments
                    .args
                    .iter()
                    .map(|base| {
                        let Expr::Name(name) = base else {
                            return ParameterParent::Unresolved;
                        };
                        if let Some(parent) = self.class_for_name(name) {
                            ParameterParent::Local(
                                parent,
                                self.classes[&parent].start() < class.start(),
                            )
                        } else if name.id.as_str() == "object"
                            && !self.loads.contains_key(&name.range())
                        {
                            ParameterParent::Object
                        } else {
                            ParameterParent::Unresolved
                        }
                    })
                    .collect()
            })
    }

    fn collect_uncertainty(&mut self, parsed: &Parsed<ModModule>) {
        for_each_stmt_expr(&parsed.syntax().body, &mut |expr| match expr {
            Expr::Name(name) if name.ctx == ExprContext::Del => {
                if let Some(&scope) = self.loads.get(&name.range()) {
                    self.invalid_bindings.insert((scope, name.id.to_string()));
                }
            }
            Expr::Attribute(attribute)
                if matches!(attribute.ctx, ExprContext::Store | ExprContext::Del) =>
            {
                if let Expr::Name(owner) = attribute.value.as_ref()
                    && let Some(class) = self.class_for_name(owner)
                {
                    self.invalid_bindings
                        .insert((class, attribute.attr.to_string()));
                    if attribute.attr.as_str() == "__bases__" {
                        let site = &self.table.def_sites[self.class_sites[&class]];
                        self.invalid_bindings
                            .insert((site.enclosing_scope, site.name.clone()));
                    }
                }
            }
            Expr::Call(call)
                if matches!(call.func.as_ref(), Expr::Name(name)
                if matches!(name.id.as_str(), "eval" | "exec" | "globals" | "locals" | "setattr" | "delattr")) =>
            {
                self.dynamic = true;
            }
            _ => {}
        });
        self.collect_declared_writes();
    }

    fn collect_declared_writes(&mut self) {
        for (scope_index, scope) in self.table.scopes.iter().enumerate() {
            for name in scope.bindings.keys() {
                if scope_index != 0 && scope.declares_global(name) {
                    self.invalid_bindings.insert((0, name.clone()));
                }
                if scope.declares_nonlocal(name)
                    && let Some(parent) = self.nonlocal_binding(scope.parent, name)
                {
                    self.invalid_bindings.insert((parent, name.clone()));
                }
            }
        }
    }

    fn nonlocal_binding(&self, mut current: Option<usize>, name: &str) -> Option<usize> {
        while let Some(parent) = current {
            let enclosing = &self.table.scopes[parent];
            if enclosing.kind == ScopeKind::Function && enclosing.bindings.contains_key(name) {
                return Some(parent);
            }
            current = enclosing.parent;
        }
        None
    }

    fn unique_definition(&self, scope: usize, name: &str) -> Option<TextRange> {
        if self.invalid_bindings.contains(&(scope, name.to_string())) {
            return None;
        }
        let bindings = self.table.scopes[scope].bindings.get(name)?;
        let [binding] = bindings.as_slice() else {
            return None;
        };
        (binding.kind == BindingKind::Definition
            && !self.uncertain_definitions.contains(&binding.range))
        .then_some(binding.range)
    }

    fn class_for_name(&self, name: &ExprName) -> Option<usize> {
        let scope = *self.loads.get(&name.range())?;
        let range = self.unique_definition(scope, name.id.as_str())?;
        self.class_names.get(&range).copied()
    }

    fn suppresses(&self, function: &StmtFunctionDef, maximum: u32) -> bool {
        if self.dynamic {
            return false;
        }
        let Some(&site_index) = self.function_sites.get(&function.name.range()) else {
            return false;
        };
        let site = &self.table.def_sites[site_index];
        let Some(&class_site_index) = self.class_sites.get(&site.enclosing_scope) else {
            return false;
        };
        let class_site = &self.table.def_sites[class_site_index];
        if self.unique_definition(class_site.enclosing_scope, &class_site.name)
            != Some(class_site.name_range)
            || self.unique_definition(site.enclosing_scope, &site.name) != Some(site.name_range)
            || self.known_mro(site.enclosing_scope).is_none()
        {
            return false;
        }
        for parent in &self.parents[&site.enclosing_scope] {
            let inherited = match parent {
                ParameterParent::Local(parent, true) => self.member(*parent, &site.name),
                ParameterParent::Object => continue,
                ParameterParent::Local(_, false) | ParameterParent::Unresolved => return false,
            };
            match inherited {
                Ok(Some(parent)) => {
                    let p = &parent.parameters;
                    let mut count = p.posonlyargs.len()
                        + p.args.len()
                        + p.kwonlyargs.len()
                        + usize::from(p.vararg.is_some())
                        + usize::from(p.kwarg.is_some());
                    if parent
                        .decorator_list
                        .iter()
                        .any(|decorator| decorator_contains_staticmethod(&decorator.expression))
                    {
                        count = count.saturating_sub(1);
                    }
                    return to_u32(count) > maximum;
                }
                Ok(None) => {}
                Err(()) => return false,
            }
        }
        false
    }

    fn own_member(&self, scope: usize, name: &str) -> Result<Option<&'a StmtFunctionDef>, ()> {
        if self.invalid_bindings.contains(&(scope, name.to_string())) {
            return Err(());
        }
        if !self.table.scopes[scope].bindings.contains_key(name) {
            return Ok(None);
        }
        let range = self.unique_definition(scope, name).ok_or(())?;
        self.functions.get(&range).copied().map(Some).ok_or(())
    }

    fn member(&self, scope: usize, name: &str) -> Result<Option<&'a StmtFunctionDef>, ()> {
        if let Some(function) = self.own_member(scope, name)? {
            return Ok(Some(function));
        }
        let mut pending = vec![scope];
        let mut visited = HashSet::new();
        while let Some(current) = pending.pop() {
            if !visited.insert(current) {
                continue;
            }
            for parent in &self.parents[&current] {
                match parent {
                    ParameterParent::Local(parent, true) => pending.push(*parent),
                    ParameterParent::Object => {}
                    ParameterParent::Local(_, false) | ParameterParent::Unresolved => {
                        return Err(());
                    }
                }
            }
        }
        for ancestor in self.known_mro(scope).ok_or(())?.into_iter().skip(1) {
            if ancestor == usize::MAX {
                continue;
            }
            if let Some(function) = self.own_member(ancestor, name)? {
                return Ok(Some(function));
            }
        }
        Ok(None)
    }

    fn known_bases(&self, scope: usize) -> Vec<usize> {
        if scope == usize::MAX {
            return Vec::new();
        }
        let mut bases: Vec<_> = self.parents[&scope]
            .iter()
            .filter_map(|parent| match parent {
                ParameterParent::Local(scope, _) => Some(*scope),
                ParameterParent::Object => Some(usize::MAX),
                ParameterParent::Unresolved => None,
            })
            .collect();
        if bases.is_empty() {
            bases.push(usize::MAX);
        }
        bases
    }

    fn known_mro(&self, root: usize) -> Option<Vec<usize>> {
        let mut states = HashMap::new();
        let mut pending = vec![(root, false)];
        let mut orders = HashMap::<usize, Vec<usize>>::new();
        while let Some((scope, expanded)) = pending.pop() {
            if expanded {
                let bases = self.known_bases(scope);
                let mut sequences: Vec<_> = bases
                    .iter()
                    .map(|base| orders.get(base).cloned())
                    .collect::<Option<_>>()?;
                sequences.push(bases);
                let mut order = vec![scope];
                order.extend(merge_parent_orders(&sequences)?);
                orders.insert(scope, order);
                states.insert(scope, true);
                continue;
            }
            match states.get(&scope) {
                Some(true) => continue,
                Some(false) => return None,
                None => {}
            }
            states.insert(scope, false);
            pending.push((scope, true));
            pending.extend(
                self.known_bases(scope)
                    .into_iter()
                    .rev()
                    .map(|base| (base, false)),
            );
        }
        orders.remove(&root)
    }
}

fn decorator_contains_staticmethod(expr: &Expr) -> bool {
    let mut current = expr;
    loop {
        match current {
            Expr::Name(name) => return name.id.as_str().contains("staticmethod"),
            Expr::Attribute(attribute) => {
                if attribute.attr.as_str().contains("staticmethod") {
                    return true;
                }
                current = &attribute.value;
            }
            _ => return false,
        }
    }
}

fn merge_parent_orders(sequences: &[Vec<usize>]) -> Option<Vec<usize>> {
    let mut positions = vec![0; sequences.len()];
    let mut result = Vec::new();
    loop {
        let heads: Vec<_> = sequences
            .iter()
            .enumerate()
            .filter_map(|(index, seq)| seq.get(positions[index]))
            .copied()
            .collect();
        if heads.is_empty() {
            return Some(result);
        }
        let candidate = heads.into_iter().find(|candidate| {
            sequences.iter().enumerate().all(|(index, seq)| {
                let tail = positions[index].saturating_add(1).min(seq.len());
                !seq[tail..].contains(candidate)
            })
        })?;
        result.push(candidate);
        for (index, seq) in sequences.iter().enumerate() {
            if seq.get(positions[index]) == Some(&candidate) {
                positions[index] += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hoonarqube_ir::{Pos, Range};

    fn findings(source: &str, maximum: u32) -> Vec<Issue> {
        let parsed = crate::support::parse(source);
        let index = LineIndex::from_source_text(source);
        let options = AnalyzerOptions {
            maximum_function_parameters: maximum,
            ..AnalyzerOptions::default()
        };
        check_function_parameter_counts(&parsed, &index, source, &options)
    }

    fn expected(start: (u32, u32), end: (u32, u32)) -> Issue {
        Issue {
            rule_key: "python:S107".into(),
            message:
                "Function \"wide\" has 14 parameters, which is greater than the 13 authorized."
                    .into(),
            range: Range {
                start: Pos {
                    line: start.0,
                    column: start.1,
                },
                end: Pos {
                    line: end.0,
                    column: end.1,
                },
            },
            fix: None,
            flows: Vec::new(),
            alternatives: Vec::new(),
        }
    }

    #[test]
    fn s107_leading_marker_inline_matches_reference_tree_range() {
        let source = "def wide(*, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((1, 9), (1, 52))]);
    }

    #[test]
    fn s107_leading_marker_multiline_matches_reference_tree_range() {
        let source = "def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14,\n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((2, 4), (16, 16))]);
    }

    #[test]
    fn s107_leading_marker_decorated_async_matches_reference_tree_range() {
        let source = "@decorator\nasync def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14,\n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((3, 4), (17, 16))]);
    }

    #[test]
    fn s107_leading_marker_trivia_matches_reference_tree_range() {
        let source = "def wide(\n    # * comment\n    *, # marker\n    a: str = \"*\",\n    b: str = \"*\",\n    c: str = \"*\",\n    d: str = \"*\",\n    e: str = \"*\",\n    f: str = \"*\",\n    g: str = \"*\",\n    h: str = \"*\",\n    i: str = \"*\",\n    j: str = \"*\",\n    k: str = \"*\",\n    l: str = \"*\",\n    m: str = \"*\",\n    n: str = \"*\",\n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((3, 4), (17, 17))]);
    }

    #[test]
    fn s107_leading_marker_no_trailing_comma_matches_reference_tree_range() {
        let source = "def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14\n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((2, 4), (16, 15))]);
    }

    #[test]
    fn s107_bare_marker_does_not_count_toward_budget() {
        for source in ["def f(*, a, b):\n    pass\n", "def f():\n    pass\n"] {
            assert!(findings(source, 2).is_empty());
        }
        let over = findings("def f(*, a, b, c):\n    pass\n", 2);
        assert_eq!(over.len(), 1);
        assert_eq!(
            over[0].message,
            "Function \"f\" has 3 parameters, which is greater than the 2 authorized."
        );
    }

    #[test]
    fn s107_ordinary_trailing_comma_and_formal_counts_are_preserved() {
        let source = "def f(\n    a: int,\n    b: str = 'fallback',\n):\n    pass\n";
        let ordinary = findings(source, 1);
        assert_eq!(ordinary.len(), 1);
        assert_eq!(ordinary[0].range.start, Pos { line: 2, column: 4 });
        assert_eq!(
            ordinary[0].range.end,
            Pos {
                line: 3,
                column: 24
            }
        );
        for (source, count) in [
            ("def f(a, /, b, *, c):\n    pass\n", 3),
            ("def f(*args, a, **kwargs):\n    pass\n", 3),
            ("class C:\n    def f(self, a, b):\n        pass\n", 2),
            (
                "class C:\n    @classmethod\n    def f(cls, a, b):\n        pass\n",
                2,
            ),
            (
                "class C:\n    @staticmethod\n    def f(a, b):\n        pass\n",
                2,
            ),
        ] {
            assert!(findings(source, count).is_empty());
            assert_eq!(findings(source, count - 1).len(), 1);
        }
    }

    fn assert_messages(source: &str, maximum: u32, expected: &[(u32, &str)]) {
        let actual = findings(source, maximum);
        let summaries: Vec<_> = actual
            .iter()
            .map(|issue| (issue.range.start.line, issue.message.as_str()))
            .collect();
        assert_eq!(summaries, expected, "{source}");
        for issue in actual {
            assert_eq!(issue.rule_key, "python:S107");
            assert!(issue.fix.is_none());
            assert!(issue.flows.is_empty());
            assert!(issue.alternatives.is_empty());
        }
    }

    #[test]
    fn s107_parent_signature_suppresses_constructor_but_retains_parent() {
        let source = "class Base:\n    def __init__(self, a, b, c, d):\n        pass\nclass Child(Base):\n    def __init__(self, a, b, c, d, e):\n        pass\n";
        let actual = findings(source, 3);
        assert_eq!(
            actual,
            vec![Issue {
                rule_key: "python:S107".into(),
                message:
                    "Method \"__init__\" has 4 parameters, which is greater than the 3 authorized."
                        .into(),
                range: Range {
                    start: Pos {
                        line: 2,
                        column: 17
                    },
                    end: Pos {
                        line: 2,
                        column: 33
                    },
                },
                fix: None,
                flows: Vec::new(),
                alternatives: Vec::new(),
            }]
        );
    }

    #[test]
    fn s107_parent_signature_applies_to_ordinary_methods_without_super_call() {
        assert_messages(
            "class Root:\n    def dispatch(self, a, b, c):\n        pass\nclass Leaf(Root):\n    def dispatch(self, a, b, c, d):\n        pass\n    def unrelated(self, a, b, c, d):\n        super().unrelated()\n",
            2,
            &[
                (
                    2,
                    "Method \"dispatch\" has 3 parameters, which is greater than the 2 authorized.",
                ),
                (
                    7,
                    "Method \"unrelated\" has 4 parameters, which is greater than the 2 authorized.",
                ),
            ],
        );
    }

    #[test]
    fn s107_parent_raw_formals_straddle_custom_maximum() {
        // The parent with four raw formals is not itself over the ordinary
        // three-argument budget, yet its overriding child is excluded.
        assert_messages(
            "class At:\n    def change(self, a, b):\n        pass\nclass Report(At):\n    def change(self, a, b, c, d):\n        pass\nclass Above:\n    def change(self, a, b, c):\n        pass\nclass Suppressed(Above):\n    def change(self, a, b, c, d):\n        pass\n",
            3,
            &[(
                5,
                "Method \"change\" has 4 parameters, which is greater than the 3 authorized.",
            )],
        );
    }

    #[test]
    fn s107_parent_static_adjustment_precedes_comparison() {
        assert_messages(
            "class At:\n    @staticmethod\n    def change(a, b, c, d):\n        pass\nclass Report(At):\n    def change(self, a, b, c, d):\n        pass\nclass Above:\n    @staticmethod\n    def change(a, b, c, d, e):\n        pass\nclass Suppressed(Above):\n    def change(self, a, b, c, d):\n        pass\n",
            3,
            &[
                (
                    3,
                    "Function \"change\" has 4 parameters, which is greater than the 3 authorized.",
                ),
                (
                    6,
                    "Method \"change\" has 4 parameters, which is greater than the 3 authorized.",
                ),
                (
                    10,
                    "Function \"change\" has 5 parameters, which is greater than the 3 authorized.",
                ),
            ],
        );
        // The installed parent check searches the decorator identity for
        // `staticmethod`; keep this distinct from ordinary receiver handling.
        assert_messages(
            "class Base:\n    @custom_staticmethod\n    def change(self, a, b, c):\n        pass\nclass Child(Base):\n    def change(self, a, b, c, d):\n        pass\n",
            3,
            &[(
                6,
                "Method \"change\" has 4 parameters, which is greater than the 3 authorized.",
            )],
        );
    }

    #[test]
    fn s107_child_receiver_handling_survives_parent_exclusion() {
        assert_messages(
            "class Base:\n    def change(self):\n        pass\nclass Child(Base):\n    @staticmethod\n    def change(a, b, c):\n        pass\n    @classmethod\n    def other(cls, a, b, c):\n        pass\n",
            2,
            &[
                (
                    6,
                    "Function \"change\" has 3 parameters, which is greater than the 2 authorized.",
                ),
                (
                    9,
                    "Method \"other\" has 3 parameters, which is greater than the 2 authorized.",
                ),
            ],
        );
    }

    #[test]
    fn s107_parent_signature_includes_static_and_class_method_children() {
        assert_messages(
            "class Base:\n    def change(self, a, b):\n        pass\nclass StaticChild(Base):\n    @staticmethod\n    def change(a, b, c):\n        pass\nclass ClassChild(Base):\n    @classmethod\n    def change(cls, a, b, c):\n        pass\ndef change(a, b, c):\n    pass\n",
            2,
            &[(
                12,
                "Function \"change\" has 3 parameters, which is greater than the 2 authorized.",
            )],
        );
    }

    #[test]
    fn s107_first_resolved_eligible_parent_controls_the_decision() {
        assert_messages(
            "class Narrow:\n    def change(self):\n        pass\nclass Wide:\n    def change(self, a, b, c):\n        pass\nclass First(Narrow, Wide):\n    def change(self, a, b, c, d):\n        pass\nclass Second(Wide, Narrow):\n    def change(self, a, b, c, d):\n        pass\nclass Empty:\n    pass\nclass Third(Empty, Wide):\n    def change(self, a, b, c, d):\n        pass\n",
            2,
            &[
                (
                    5,
                    "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
                ),
                (
                    8,
                    "Method \"change\" has 4 parameters, which is greater than the 2 authorized.",
                ),
            ],
        );
    }

    #[test]
    fn s107_parent_member_can_be_inherited_through_known_classes() {
        assert_messages(
            "class Root:\n    def change(self, a, b, c):\n        pass\nclass Middle(Root):\n    pass\nclass Leaf(Middle):\n    def change(self, a, b, c, d):\n        pass\n",
            2,
            &[(
                2,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
            )],
        );
    }

    #[test]
    fn s107_direct_parent_member_does_not_require_external_ancestor() {
        assert_messages(
            "from external import Abstract\nclass Root(Abstract):\n    def change(self, a, b, c):\n        pass\nclass Leaf(Root):\n    def change(self, a, b, c, d):\n        pass\n",
            2,
            &[(
                3,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
            )],
        );
    }

    #[test]
    fn s107_unknown_imported_attribute_and_dynamic_bases_keep_findings() {
        for source in [
            "class Child(Unknown):\n    def change(self, a, b, c):\n        pass\n",
            "from external import Base\nclass Child(Base):\n    def change(self, a, b, c):\n        pass\n",
            "import external\nclass Child(external.Base):\n    def change(self, a, b, c):\n        pass\n",
            "class Child(factory()):\n    def change(self, a, b, c):\n        pass\n",
        ] {
            let actual = findings(source, 2);
            assert_eq!(actual.len(), 1, "{source}");
            assert_eq!(
                actual[0].message,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized."
            );
        }
    }

    #[test]
    fn s107_unresolved_first_parent_cannot_be_skipped_for_wide_parent() {
        assert_messages(
            "class Wide:\n    def change(self, a, b, c):\n        pass\nclass Child(Unknown, Wide):\n    def change(self, a, b, c, d):\n        pass\n",
            2,
            &[
                (
                    2,
                    "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
                ),
                (
                    5,
                    "Method \"change\" has 4 parameters, which is greater than the 2 authorized.",
                ),
            ],
        );
    }

    #[test]
    fn s107_rebound_and_duplicate_class_bindings_keep_child_findings() {
        let parent = "class Base:\n    def change(self, a, b):\n        pass\n";
        for rebound in [
            "Base = replacement\n",
            "del Base\n",
            "class Base:\n    pass\n",
            "if condition:\n    Base = replacement\n",
            "(Base := replacement)\n",
        ] {
            let source = format!(
                "{parent}{rebound}class Child(Base):\n    def change(self, a, b, c):\n        pass\n"
            );
            let actual = findings(&source, 2);
            assert_eq!(actual.len(), 1, "{source}");
            assert_eq!(
                actual[0].message,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized."
            );
        }
    }

    #[test]
    fn s107_rebound_and_duplicate_method_bindings_keep_child_findings() {
        for source in [
            "class Base:\n    def change(self, a, b):\n        pass\n    change = replacement\nclass Child(Base):\n    def change(self, a, b, c):\n        pass\n",
            "class Base:\n    def change(self, a, b):\n        pass\n    def change(self):\n        pass\nclass Child(Base):\n    def change(self, a, b, c):\n        pass\n",
            "class Base:\n    def change(self, a, b):\n        pass\nBase.change = replacement\nclass Child(Base):\n    def change(self, a, b, c):\n        pass\n",
        ] {
            let actual = findings(source, 2);
            assert_eq!(actual.len(), 1, "{source}");
            assert_eq!(
                actual[0].message,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized."
            );
        }
    }

    #[test]
    fn s107_nested_functions_keep_function_budget_and_lexical_class_isolation() {
        assert_messages(
            "class Base:\n    def change(self, a, b):\n        pass\nclass Child(Base):\n    def change(self, a, b, c):\n        def change(a, b, c):\n            pass\n",
            2,
            &[(
                6,
                "Function \"change\" has 3 parameters, which is greater than the 2 authorized.",
            )],
        );
        assert_messages(
            "class Base:\n    def change(self, a, b):\n        pass\ndef factory():\n    class Base:\n        def change(self):\n            pass\n    class Child(Base):\n        def change(self, a, b, c):\n            pass\nclass Child(Base):\n    def change(self, a, b, c):\n        pass\n",
            2,
            &[(
                9,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
            )],
        );
    }

    #[test]
    fn s107_local_classes_resolve_without_crossing_function_scopes() {
        assert_messages(
            "def first():\n    class Base:\n        def change(self, a, b):\n            pass\n    class Child(Base):\n        def change(self, a, b, c):\n            pass\ndef second():\n    class Child(Base):\n        def change(self, a, b, c):\n            pass\n",
            2,
            &[(
                10,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
            )],
        );
        assert_messages(
            "class Base:\n    def change(self, a, b):\n        pass\ndef factory(Base):\n    class Child(Base):\n        def change(self, a, b, c):\n            pass\n",
            2,
            &[(
                6,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
            )],
        );
    }

    #[test]
    fn s107_cycles_and_inconsistent_hierarchies_keep_findings() {
        assert_messages(
            "class A(B):\n    def change(self, a, b):\n        pass\nclass B(A):\n    def change(self, a, b, c):\n        pass\nclass Child(B):\n    def change(self, a, b, c):\n        pass\n",
            2,
            &[
                (
                    5,
                    "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
                ),
                (
                    8,
                    "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
                ),
            ],
        );
        assert_messages(
            "class A:\n    def change(self, a, b):\n        pass\nclass B(A):\n    pass\nclass Conflict(A, B):\n    pass\nclass Child(Conflict):\n    def change(self, a, b, c):\n        pass\n",
            2,
            &[(
                9,
                "Method \"change\" has 3 parameters, which is greater than the 2 authorized.",
            )],
        );
    }
}
