use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::{
    collect_target_names, dict_string_entry, for_each_dict_literal, for_each_stmt_in_scope,
    grants_to_all_principals, issue_at, keyword_value, named_parameters, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
}

#[derive(Clone, Copy)]
struct LexicalScope {
    range: TextRange,
    parent: Option<usize>,
    kind: ScopeKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IamBindingKind {
    CdkRoot,
    IamModule,
    PolicyStatement,
    Effect,
    AnyPrincipal,
    StarPrincipal,
}

#[derive(Clone, Copy)]
struct IamBindingEvent {
    start: TextSize,
    kind: Option<IamBindingKind>,
}

#[derive(Default)]
struct IamBindings {
    module_aliases: HashSet<String>,
    imported_module_roots: HashSet<String>,
    policy_statement_names: HashSet<String>,
    effect_names: HashSet<String>,
    any_principal_names: HashSet<String>,
    star_principal_names: HashSet<String>,
    events: HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scopes: Vec<LexicalScope>,
}

impl IamBindings {
    fn collect(file_ctx: &FileContext<'_>) -> Self {
        let mut bindings = Self {
            scopes: lexical_scopes(file_ctx),
            ..Self::default()
        };
        collect_import_bindings(&mut bindings, &file_ctx.imports);
        collect_import_events(&mut bindings.events, &bindings.scopes, &file_ctx.imports);
        let tracked_names = bindings.tracked_names();
        for function in &file_ctx.functions {
            collect_function_binding_events(&mut bindings, function, &tracked_names);
        }
        for stmt in &file_ctx.stmts {
            record_rebinding_events(stmt, &bindings.scopes, &tracked_names, &mut bindings.events);
        }
        sort_binding_events(&mut bindings.events);
        bindings
    }

    fn tracked_names(&self) -> HashSet<String> {
        self.module_aliases
            .iter()
            .chain(&self.imported_module_roots)
            .chain(&self.policy_statement_names)
            .chain(&self.effect_names)
            .chain(&self.any_principal_names)
            .chain(&self.star_principal_names)
            .cloned()
            .collect()
    }

    fn scope_for_offset(&self, at: TextSize) -> usize {
        self.scopes
            .iter()
            .enumerate()
            .filter(|(_, scope)| scope.range.start() <= at && at <= scope.range.end())
            .min_by_key(|(_, scope)| scope.range.end().to_u32() - scope.range.start().to_u32())
            .map_or(0, |(id, _)| id)
    }

    fn binding_at(&self, name: &str, at: TextSize) -> Option<IamBindingKind> {
        let mut scope_id = self.scope_for_offset(at);
        loop {
            if let Some(events) = self
                .events
                .get(&scope_id)
                .and_then(|events_by_name| events_by_name.get(name))
            {
                let index = events.partition_point(|event| event.start <= at);
                if let Some(event) = index.checked_sub(1).and_then(|index| events.get(index)) {
                    return event.kind;
                }
            }
            let parent = self.scopes[scope_id].parent?;
            scope_id = parent;
        }
    }

    fn is_constructor(
        &self,
        function: &Expr,
        attribute_name: &str,
        imported_names: &HashSet<String>,
        kind: IamBindingKind,
        at: TextSize,
    ) -> bool {
        match function {
            Expr::Name(name) => {
                imported_names.contains(name.id.as_str())
                    && self.binding_at(name.id.as_str(), at) == Some(kind)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == attribute_name
                    && self.is_iam_module(&attribute.value, at)
            }
            _ => false,
        }
    }

    fn is_policy_statement(&self, function: &Expr, at: TextSize) -> bool {
        self.is_constructor(
            function,
            "PolicyStatement",
            &self.policy_statement_names,
            IamBindingKind::PolicyStatement,
            at,
        )
    }

    fn is_any_principal(&self, function: &Expr, at: TextSize) -> bool {
        self.is_constructor(
            function,
            "AnyPrincipal",
            &self.any_principal_names,
            IamBindingKind::AnyPrincipal,
            at,
        )
    }

    fn is_star_principal(&self, function: &Expr, at: TextSize) -> bool {
        self.is_constructor(
            function,
            "StarPrincipal",
            &self.star_principal_names,
            IamBindingKind::StarPrincipal,
            at,
        )
    }

    fn is_allow_effect(&self, value: &Expr, at: TextSize) -> bool {
        let Expr::Attribute(attribute) = value else {
            return false;
        };
        if attribute.attr.as_str() != "ALLOW" {
            return false;
        }
        match attribute.value.as_ref() {
            Expr::Name(name) => {
                self.effect_names.contains(name.id.as_str())
                    && self.binding_at(name.id.as_str(), at) == Some(IamBindingKind::Effect)
            }
            Expr::Attribute(parent) => {
                parent.attr.as_str() == "Effect" && self.is_iam_module(&parent.value, at)
            }
            _ => false,
        }
    }

    fn public_principal_range(&self, value: &Expr, at: TextSize) -> Option<TextRange> {
        let elements = match value {
            Expr::List(list) => list.elts.as_slice(),
            Expr::Tuple(tuple) => tuple.elts.as_slice(),
            _ => return None,
        };
        elements.iter().find_map(|element| {
            let Expr::Call(call) = element else {
                return None;
            };
            (self.is_any_principal(&call.func, at) || self.is_star_principal(&call.func, at))
                .then_some(call.range())
        })
    }

    fn is_iam_module(&self, value: &Expr, at: TextSize) -> bool {
        match value {
            Expr::Name(name) => {
                self.module_aliases.contains(name.id.as_str())
                    && self.binding_at(name.id.as_str(), at) == Some(IamBindingKind::IamModule)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == "aws_iam"
                    && matches!(
                        attribute.value.as_ref(),
                        Expr::Name(name)
                            if self.imported_module_roots.contains(name.id.as_str())
                                && self.binding_at(name.id.as_str(), at)
                                    == Some(IamBindingKind::CdkRoot)
                    )
            }
            _ => false,
        }
    }
}
fn collect_function_binding_events(
    bindings: &mut IamBindings,
    function: &ruff_python_ast::StmtFunctionDef,
    tracked_names: &HashSet<String>,
) {
    let Some(range) = body_range(function.body.as_slice()) else {
        return;
    };
    let scope_id = scope_for_range(&bindings.scopes, range);
    let activation = bindings.scopes[scope_id].range.start();
    collect_parameter_binding_events(
        bindings,
        scope_id,
        activation,
        &function.parameters,
        tracked_names,
    );
    collect_store_binding_events(
        bindings,
        scope_id,
        activation,
        function.body.as_slice(),
        tracked_names,
    );
}

fn collect_parameter_binding_events(
    bindings: &mut IamBindings,
    scope_id: usize,
    activation: TextSize,
    parameters: &ruff_python_ast::Parameters,
    tracked_names: &HashSet<String>,
) {
    for parameter in named_parameters(parameters) {
        record_tracked_binding_event(
            bindings,
            scope_id,
            activation,
            parameter.parameter.name.as_str(),
            tracked_names,
        );
    }
    for parameter in [parameters.vararg.as_deref(), parameters.kwarg.as_deref()]
        .into_iter()
        .flatten()
    {
        record_tracked_binding_event(
            bindings,
            scope_id,
            activation,
            parameter.name.as_str(),
            tracked_names,
        );
    }
}

fn collect_store_binding_events(
    bindings: &mut IamBindings,
    scope_id: usize,
    activation: TextSize,
    body: &[Stmt],
    tracked_names: &HashSet<String>,
) {
    for_each_stmt_in_scope(body, &mut |stmt| {
        for name in stmt_store_names(stmt) {
            record_tracked_binding_event(bindings, scope_id, activation, &name, tracked_names);
        }
    });
}

fn record_tracked_binding_event(
    bindings: &mut IamBindings,
    scope_id: usize,
    start: TextSize,
    name: &str,
    tracked_names: &HashSet<String>,
) {
    if tracked_names.contains(name) {
        push_binding_event(&mut bindings.events, scope_id, name, start, None);
    }
}

fn collect_plain_import_bindings(bindings: &mut IamBindings, import: &ruff_python_ast::StmtImport) {
    for alias in &import.names {
        match alias.name.as_str() {
            "aws_cdk" => {
                bindings
                    .imported_module_roots
                    .insert(alias.asname.as_deref().unwrap_or("aws_cdk").to_string());
            }
            "aws_cdk.aws_iam" => {
                if let Some(asname) = alias.asname.as_deref() {
                    bindings.module_aliases.insert(asname.to_string());
                } else {
                    bindings.imported_module_roots.insert("aws_cdk".to_string());
                }
            }
            _ => {}
        }
    }
}

fn collect_from_import_bindings(
    bindings: &mut IamBindings,
    import: &ruff_python_ast::StmtImportFrom,
) {
    if import.level != 0 {
        return;
    }
    let Some(module) = import
        .module
        .as_ref()
        .map(ruff_python_ast::Identifier::as_str)
    else {
        return;
    };
    match module {
        "aws_cdk" => collect_cdk_module_bindings(bindings, &import.names),
        "aws_cdk.aws_iam" => collect_iam_module_bindings(bindings, &import.names),
        _ => {}
    }
}

fn collect_cdk_module_bindings(bindings: &mut IamBindings, aliases: &[ruff_python_ast::Alias]) {
    for alias in aliases {
        if matches!(alias.name.as_str(), "aws_iam" | "*") {
            bindings
                .module_aliases
                .insert(alias.asname.as_deref().unwrap_or("aws_iam").to_string());
        }
    }
}

fn collect_iam_module_bindings(bindings: &mut IamBindings, aliases: &[ruff_python_ast::Alias]) {
    for alias in aliases {
        if alias.name.as_str() == "*" {
            bindings
                .policy_statement_names
                .insert("PolicyStatement".to_string());
            bindings.effect_names.insert("Effect".to_string());
            bindings
                .any_principal_names
                .insert("AnyPrincipal".to_string());
            bindings
                .star_principal_names
                .insert("StarPrincipal".to_string());
            continue;
        }
        let local = alias
            .asname
            .as_deref()
            .unwrap_or(alias.name.as_str())
            .to_string();
        match alias.name.as_str() {
            "PolicyStatement" => {
                bindings.policy_statement_names.insert(local);
            }
            "Effect" => {
                bindings.effect_names.insert(local);
            }
            "AnyPrincipal" => {
                bindings.any_principal_names.insert(local);
            }
            "StarPrincipal" => {
                bindings.star_principal_names.insert(local);
            }
            _ => {}
        }
    }
}

fn collect_import_bindings(bindings: &mut IamBindings, imports: &[AnyImport<'_>]) {
    for import in imports {
        match import {
            AnyImport::Plain(import) => collect_plain_import_bindings(bindings, import),
            AnyImport::From(import) => collect_from_import_bindings(bindings, import),
        }
    }
}

fn collect_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scopes: &[LexicalScope],
    imports: &[AnyImport<'_>],
) {
    for import in imports {
        match import {
            AnyImport::Plain(import) => collect_plain_import_events(events, scopes, import),
            AnyImport::From(import) => collect_from_import_events(events, scopes, import),
        }
    }
}

fn collect_plain_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scopes: &[LexicalScope],
    import: &ruff_python_ast::StmtImport,
) {
    let import_range = import.range();
    let scope_id = scope_for_range(scopes, import_range);
    for alias in &import.names {
        let local = plain_import_local(alias);
        let kind = plain_import_kind(alias);
        push_binding_event(events, scope_id, local, import_range.end(), kind);
    }
}

fn plain_import_local(alias: &ruff_python_ast::Alias) -> &str {
    alias.asname.as_deref().unwrap_or_else(|| {
        alias
            .name
            .as_str()
            .split('.')
            .next()
            .unwrap_or(alias.name.as_str())
    })
}

fn plain_import_kind(alias: &ruff_python_ast::Alias) -> Option<IamBindingKind> {
    match alias.name.as_str() {
        "aws_cdk.aws_iam" if alias.asname.is_some() => Some(IamBindingKind::IamModule),
        "aws_cdk" | "aws_cdk.aws_iam" => Some(IamBindingKind::CdkRoot),
        _ => None,
    }
}

fn collect_from_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scopes: &[LexicalScope],
    import: &ruff_python_ast::StmtImportFrom,
) {
    let import_range = import.range();
    let scope_id = scope_for_range(scopes, import_range);
    let module = import
        .module
        .as_ref()
        .map(ruff_python_ast::Identifier::as_str);
    if import.level != 0 || module.is_none() {
        collect_unknown_from_import_events(events, scope_id, &import.names, import_range.end());
        return;
    }
    let module = module.expect("checked above");
    collect_known_from_import_events(events, scope_id, module, &import.names, import_range.end());
}

fn collect_unknown_from_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scope_id: usize,
    aliases: &[ruff_python_ast::Alias],
    start: TextSize,
) {
    for alias in aliases {
        if alias.name.as_str() == "*" {
            collect_unknown_star_import_events(events, scope_id, start);
            continue;
        }
        let local = alias.asname.as_deref().unwrap_or(alias.name.as_str());
        push_binding_event(events, scope_id, local, start, None);
    }
}

fn collect_unknown_star_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scope_id: usize,
    start: TextSize,
) {
    for name in [
        "aws_iam",
        "PolicyStatement",
        "Effect",
        "AnyPrincipal",
        "StarPrincipal",
    ] {
        push_binding_event(events, scope_id, name, start, None);
    }
}

fn collect_known_from_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scope_id: usize,
    module: &str,
    aliases: &[ruff_python_ast::Alias],
    start: TextSize,
) {
    for alias in aliases {
        if alias.name.as_str() == "*" {
            collect_known_star_import_events(events, scope_id, module, start);
            continue;
        }
        let local = alias.asname.as_deref().unwrap_or(alias.name.as_str());
        let kind = known_from_import_kind(module, alias.name.as_str());
        push_binding_event(events, scope_id, local, start, kind);
    }
}

fn collect_known_star_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scope_id: usize,
    module: &str,
    start: TextSize,
) {
    match module {
        "aws_cdk" => {
            push_binding_event(
                events,
                scope_id,
                "aws_iam",
                start,
                Some(IamBindingKind::IamModule),
            );
        }
        "aws_cdk.aws_iam" => {
            push_binding_event(
                events,
                scope_id,
                "PolicyStatement",
                start,
                Some(IamBindingKind::PolicyStatement),
            );
            push_binding_event(
                events,
                scope_id,
                "Effect",
                start,
                Some(IamBindingKind::Effect),
            );
            push_binding_event(
                events,
                scope_id,
                "AnyPrincipal",
                start,
                Some(IamBindingKind::AnyPrincipal),
            );
            push_binding_event(
                events,
                scope_id,
                "StarPrincipal",
                start,
                Some(IamBindingKind::StarPrincipal),
            );
        }
        _ => {}
    }
}

fn known_from_import_kind(module: &str, name: &str) -> Option<IamBindingKind> {
    match (module, name) {
        ("aws_cdk", "aws_iam") => Some(IamBindingKind::IamModule),
        ("aws_cdk.aws_iam", "PolicyStatement") => Some(IamBindingKind::PolicyStatement),
        ("aws_cdk.aws_iam", "Effect") => Some(IamBindingKind::Effect),
        ("aws_cdk.aws_iam", "AnyPrincipal") => Some(IamBindingKind::AnyPrincipal),
        ("aws_cdk.aws_iam", "StarPrincipal") => Some(IamBindingKind::StarPrincipal),
        _ => None,
    }
}

fn sort_binding_events(events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>) {
    for events_by_name in events.values_mut() {
        for events in events_by_name.values_mut() {
            events.sort_by_key(|event| event.start);
        }
    }
}

fn lexical_scopes(file_ctx: &FileContext<'_>) -> Vec<LexicalScope> {
    let end = file_ctx
        .stmts
        .iter()
        .map(|stmt| stmt.range().end())
        .max()
        .unwrap_or_else(|| TextSize::new(0));
    let mut ranges = vec![(TextRange::new(TextSize::new(0), end), ScopeKind::Module)];
    for function in &file_ctx.functions {
        if let Some(range) = body_range(function.body.as_slice()) {
            ranges.push((range, ScopeKind::Function));
        }
    }
    for class in &file_ctx.classes {
        if let Some(range) = body_range(class.body.as_slice()) {
            ranges.push((range, ScopeKind::Class));
        }
    }
    let mut ordered = ranges
        .iter()
        .enumerate()
        .map(|(id, (range, kind))| (id, *range, *kind))
        .collect::<Vec<_>>();
    ordered.sort_unstable_by(|(_, left, _), (_, right, _)| {
        left.start()
            .cmp(&right.start())
            .then_with(|| right.end().cmp(&left.end()))
    });
    let mut parents = vec![None; ranges.len()];
    let mut active: Vec<usize> = Vec::new();
    for (id, range, _) in ordered {
        while active
            .last()
            .is_some_and(|candidate| !ranges[*candidate].0.contains_range(range))
        {
            active.pop();
        }
        if id != 0 {
            parents[id] = active
                .iter()
                .rev()
                .find(|candidate| ranges[**candidate].1 != ScopeKind::Class)
                .copied();
        }
        active.push(id);
    }
    ranges
        .into_iter()
        .enumerate()
        .map(|(id, (range, kind))| LexicalScope {
            range,
            parent: parents[id],
            kind,
        })
        .collect()
}

fn body_range(body: &[Stmt]) -> Option<TextRange> {
    Some(TextRange::new(
        body.first()?.range().start(),
        body.last()?.range().end(),
    ))
}

fn push_binding_event(
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
    scope_id: usize,
    name: &str,
    start: TextSize,
    kind: Option<IamBindingKind>,
) {
    events
        .entry(scope_id)
        .or_default()
        .entry(name.to_string())
        .or_default()
        .push(IamBindingEvent { start, kind });
}
fn record_rebinding_events(
    stmt: &Stmt,
    scopes: &[LexicalScope],
    tracked_names: &HashSet<String>,
    events: &mut HashMap<usize, HashMap<String, Vec<IamBindingEvent>>>,
) {
    let mut names = Vec::new();
    let activation = match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                collect_target_names(target, &mut names);
            }
            Some(assign.value.end())
        }
        Stmt::AnnAssign(assign) => {
            collect_target_names(&assign.target, &mut names);
            assign.value.as_deref().map(Ranged::end)
        }
        Stmt::AugAssign(assign) => {
            collect_target_names(&assign.target, &mut names);
            Some(assign.value.end())
        }
        Stmt::For(for_stmt) => {
            collect_target_names(&for_stmt.target, &mut names);
            Some(for_stmt.iter.end())
        }
        Stmt::FunctionDef(function) => {
            names.push(function.name.to_string());
            Some(
                function
                    .body
                    .first()
                    .map_or_else(|| stmt.range().end(), Ranged::start),
            )
        }
        Stmt::ClassDef(class) => {
            names.push(class.name.to_string());
            Some(stmt.range().end())
        }
        _ => return,
    };
    let scope_id = scope_for_range(
        scopes,
        TextRange::new(stmt.range().start(), stmt.range().start()),
    );
    let activation = activation.or_else(|| {
        (scopes[scope_id].kind == ScopeKind::Function).then(|| scopes[scope_id].range.start())
    });
    let Some(activation) = activation else {
        return;
    };
    for name in names {
        if tracked_names.contains(&name) {
            push_binding_event(events, scope_id, &name, activation, None);
        }
    }
}

fn scope_for_range(scopes: &[LexicalScope], range: TextRange) -> usize {
    scopes
        .iter()
        .enumerate()
        .filter(|(_, scope)| scope.range.contains_range(range))
        .min_by_key(|(_, scope)| scope.range.end().to_u32() - scope.range.start().to_u32())
        .map_or(0, |(id, _)| id)
}

fn check_cdk_policy(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
) -> Vec<Issue> {
    let bindings = IamBindings::collect(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let at = call.range().start();
        if !bindings.is_policy_statement(&call.func, at) {
            continue;
        }
        if let Some(effect) = keyword_value(&call.arguments, "effect")
            && !bindings.is_allow_effect(effect, at)
        {
            continue;
        }
        let Some(principals) = keyword_value(&call.arguments, "principals") else {
            continue;
        };
        let Some(principal_range) = bindings.public_principal_range(principals, at) else {
            continue;
        };
        issues.push(issue_at(
            "python:S6270",
            "Make sure granting public access is safe here.",
            principal_range,
            index,
            source,
        ));
    }
    issues
}

// --- python:S6270 — resource-based policies granting public access --------------

pub(crate) fn check_s6270_public_resource_policy(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
) -> Vec<Issue> {
    let mut issues = check_cdk_policy(parsed, index, source, file_ctx);
    for_each_dict_literal(parsed.syntax().body.as_slice(), &mut |dict| {
        if dict_string_entry(dict, "Principal").is_some_and(grants_to_all_principals) {
            issues.push(issue_at(
                "python:S6270",
                "Restrict this resource policy instead of granting public access.",
                dict.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6270_flags_public_cdk_policy_statements() {
        let flagged = concat!(
            "from aws_cdk.aws_iam import AnyPrincipal, Effect, PolicyStatement\n",
            "PolicyStatement(effect=Effect.ALLOW, actions=[\"s3:*\"] , principals=[AnyPrincipal()])\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6270").len(), 1);
        let safe = concat!(
            "from aws_cdk.aws_iam import AccountRootPrincipal, Effect, PolicyStatement\n",
            "PolicyStatement(effect=Effect.ALLOW, actions=[\"s3:*\"] , principals=[AccountRootPrincipal()])\n",
        );
        assert!(findings(&scan(safe), "python:S6270").is_empty());
        let unknown = concat!(
            "from aws_cdk.aws_iam import AnyPrincipal, Effect, PolicyStatement\n",
            "def make_policy(principal):\n",
            "    return PolicyStatement(effect=Effect.ALLOW, principals=[principal])\n",
        );
        assert!(findings(&scan(unknown), "python:S6270").is_empty());
    }

    #[test]
    fn s6270_requires_trusted_principal_provenance() {
        let source = concat!(
            "from aws_cdk.aws_iam import AnyPrincipal as PublicPrincipal, Effect, PolicyStatement\n",
            "PolicyStatement(effect=Effect.ALLOW, principals=[PublicPrincipal()])\n",
            "PublicPrincipal = LocalPrincipal\n",
            "PolicyStatement(effect=Effect.ALLOW, principals=[PublicPrincipal()])\n",
            "import aws_cdk_fake.aws_iam as fake_iam\n",
            "fake_iam.PolicyStatement(effect=fake_iam.Effect.ALLOW, principals=[fake_iam.AnyPrincipal()])\n",
        );
        assert_eq!(findings(&scan(source), "python:S6270").len(), 1);
    }

    #[test]
    fn s6270_preserves_legacy_wildcard_policy_dicts() {
        let flagged = concat!(
            "policy = {\"Statement\": [{\"Effect\": \"Allow\", \"Principal\": \"*\",\n",
            "    \"Action\": \"s3:GetObject\"}]}\n",
            "policy2 = {\"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"*\"}}]}\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6270").len(), 2);
        assert!(findings(
            &scan(
                "policy = {\"Statement\": [{\"Principal\": {\"AWS\": \"arn:aws:iam::123:root\"}}]}\n"
            ),
            "python:S6270"
        )
        .is_empty());
    }
}
