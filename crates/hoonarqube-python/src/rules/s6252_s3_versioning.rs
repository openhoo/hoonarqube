use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::{
    called_name, for_each_stmt_in_scope, has_keyword, is_false_literal, issue_at, keyword_range,
    keyword_value, named_parameters, stmt_store_names, string_literal_text,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
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
enum S3BindingKind {
    CdkRoot,
    S3Module,
    DeploymentModule,
    Bucket,
    BucketDeployment,
    BucketAccessControl,
}

#[derive(Clone, Copy)]
struct S3BindingEvent {
    start: TextSize,
    kind: Option<S3BindingKind>,
}

#[derive(Default)]
pub(super) struct S3Bindings {
    module_aliases: HashSet<String>,
    deployment_module_aliases: HashSet<String>,
    imported_module_roots: HashSet<String>,
    bucket_names: HashSet<String>,
    bucket_deployment_names: HashSet<String>,
    bucket_access_control_names: HashSet<String>,
    events: HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
    scopes: Vec<LexicalScope>,
}

impl S3Bindings {
    pub(super) fn collect(file_ctx: &FileContext<'_>) -> Self {
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
            .chain(&self.deployment_module_aliases)
            .chain(&self.imported_module_roots)
            .chain(&self.bucket_names)
            .chain(&self.bucket_deployment_names)
            .chain(&self.bucket_access_control_names)
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

    fn binding_at(&self, name: &str, at: TextSize) -> Option<S3BindingKind> {
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

    pub(super) fn is_s3_bucket_constructor(&self, function: &Expr, at: TextSize) -> bool {
        match function {
            Expr::Name(name) => {
                self.binding_at(name.id.as_str(), at) == Some(S3BindingKind::Bucket)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == "Bucket" && self.is_s3_module(&attribute.value, at)
            }
            _ => false,
        }
    }

    pub(super) fn is_bucket_deployment_constructor(&self, function: &Expr, at: TextSize) -> bool {
        match function {
            Expr::Name(name) => {
                self.binding_at(name.id.as_str(), at) == Some(S3BindingKind::BucketDeployment)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == "BucketDeployment"
                    && self.is_deployment_module(&attribute.value, at)
            }
            _ => false,
        }
    }

    pub(super) fn public_access_level(&self, value: &Expr, at: TextSize) -> Option<&'static str> {
        let Expr::Attribute(attribute) = value else {
            return None;
        };
        let level = match attribute.attr.as_str() {
            "PUBLIC_READ" => "PUBLIC_READ",
            "PUBLIC_READ_WRITE" => "PUBLIC_READ_WRITE",
            "AUTHENTICATED_READ" => "AUTHENTICATED_READ",
            _ => return None,
        };
        let trusted = match attribute.value.as_ref() {
            Expr::Name(name) => {
                self.binding_at(name.id.as_str(), at) == Some(S3BindingKind::BucketAccessControl)
            }
            Expr::Attribute(parent) => {
                parent.attr.as_str() == "BucketAccessControl"
                    && self.is_s3_module(&parent.value, at)
            }
            _ => false,
        };
        trusted.then_some(level)
    }

    fn is_s3_module(&self, value: &Expr, at: TextSize) -> bool {
        match value {
            Expr::Name(name) => {
                self.binding_at(name.id.as_str(), at) == Some(S3BindingKind::S3Module)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == "aws_s3"
                    && matches!(
                        attribute.value.as_ref(),
                        Expr::Name(name)
                            if self.binding_at(name.id.as_str(), at)
                                == Some(S3BindingKind::CdkRoot)
                    )
            }
            _ => false,
        }
    }

    fn is_deployment_module(&self, value: &Expr, at: TextSize) -> bool {
        match value {
            Expr::Name(name) => {
                self.binding_at(name.id.as_str(), at) == Some(S3BindingKind::DeploymentModule)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == "aws_s3_deployment"
                    && matches!(
                        attribute.value.as_ref(),
                        Expr::Name(name)
                            if self.binding_at(name.id.as_str(), at)
                                == Some(S3BindingKind::CdkRoot)
                    )
            }
            _ => false,
        }
    }
}
fn collect_function_binding_events(
    bindings: &mut S3Bindings,
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
    bindings: &mut S3Bindings,
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
    bindings: &mut S3Bindings,
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
    bindings: &mut S3Bindings,
    scope_id: usize,
    start: TextSize,
    name: &str,
    tracked_names: &HashSet<String>,
) {
    if tracked_names.contains(name) {
        push_binding_event(&mut bindings.events, scope_id, name, start, None);
    }
}

fn collect_plain_import_bindings(bindings: &mut S3Bindings, import: &ruff_python_ast::StmtImport) {
    for alias in &import.names {
        match alias.name.as_str() {
            "aws_cdk" => {
                bindings
                    .imported_module_roots
                    .insert(alias.asname.as_deref().unwrap_or("aws_cdk").to_string());
            }
            "aws_cdk.aws_s3" => {
                if let Some(asname) = alias.asname.as_deref() {
                    bindings.module_aliases.insert(asname.to_string());
                } else {
                    bindings.imported_module_roots.insert("aws_cdk".to_string());
                }
            }
            "aws_cdk.aws_s3_deployment" => {
                if let Some(asname) = alias.asname.as_deref() {
                    bindings
                        .deployment_module_aliases
                        .insert(asname.to_string());
                } else {
                    bindings.imported_module_roots.insert("aws_cdk".to_string());
                }
            }
            _ => {}
        }
    }
}

fn collect_from_import_bindings(
    bindings: &mut S3Bindings,
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
        "aws_cdk.aws_s3" => collect_s3_module_bindings(bindings, &import.names),
        "aws_cdk.aws_s3_deployment" => {
            collect_deployment_module_bindings(bindings, &import.names);
        }
        _ => {}
    }
}

fn collect_cdk_module_bindings(bindings: &mut S3Bindings, aliases: &[ruff_python_ast::Alias]) {
    for alias in aliases {
        match alias.name.as_str() {
            "aws_s3" => {
                bindings
                    .module_aliases
                    .insert(alias.asname.as_deref().unwrap_or("aws_s3").to_string());
            }
            "aws_s3_deployment" => {
                bindings.deployment_module_aliases.insert(
                    alias
                        .asname
                        .as_deref()
                        .unwrap_or("aws_s3_deployment")
                        .to_string(),
                );
            }
            "*" => {
                bindings.module_aliases.insert("aws_s3".to_string());
                bindings
                    .deployment_module_aliases
                    .insert("aws_s3_deployment".to_string());
            }
            _ => {}
        }
    }
}

fn collect_s3_module_bindings(bindings: &mut S3Bindings, aliases: &[ruff_python_ast::Alias]) {
    for alias in aliases {
        if alias.name.as_str() == "*" {
            bindings.bucket_names.insert("Bucket".to_string());
            bindings
                .bucket_access_control_names
                .insert("BucketAccessControl".to_string());
            continue;
        }
        let local = alias
            .asname
            .as_deref()
            .unwrap_or(alias.name.as_str())
            .to_string();
        match alias.name.as_str() {
            "Bucket" => {
                bindings.bucket_names.insert(local);
            }
            "BucketAccessControl" => {
                bindings.bucket_access_control_names.insert(local);
            }
            _ => {}
        }
    }
}

fn collect_deployment_module_bindings(
    bindings: &mut S3Bindings,
    aliases: &[ruff_python_ast::Alias],
) {
    for alias in aliases {
        if alias.name.as_str() == "*" || alias.name.as_str() == "BucketDeployment" {
            bindings.bucket_deployment_names.insert(
                alias
                    .asname
                    .as_deref()
                    .unwrap_or("BucketDeployment")
                    .to_string(),
            );
        }
    }
}

fn collect_import_bindings(bindings: &mut S3Bindings, imports: &[AnyImport<'_>]) {
    for import in imports {
        match import {
            AnyImport::Plain(import) => collect_plain_import_bindings(bindings, import),
            AnyImport::From(import) => collect_from_import_bindings(bindings, import),
        }
    }
}

fn collect_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
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
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
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

fn plain_import_kind(alias: &ruff_python_ast::Alias) -> Option<S3BindingKind> {
    match alias.name.as_str() {
        "aws_cdk.aws_s3" if alias.asname.is_some() => Some(S3BindingKind::S3Module),
        "aws_cdk.aws_s3_deployment" if alias.asname.is_some() => {
            Some(S3BindingKind::DeploymentModule)
        }
        "aws_cdk" | "aws_cdk.aws_s3" | "aws_cdk.aws_s3_deployment" => Some(S3BindingKind::CdkRoot),
        _ => None,
    }
}

fn collect_from_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
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
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
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
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
    scope_id: usize,
    start: TextSize,
) {
    for name in [
        "aws_s3",
        "aws_s3_deployment",
        "Bucket",
        "BucketDeployment",
        "BucketAccessControl",
    ] {
        push_binding_event(events, scope_id, name, start, None);
    }
}

fn collect_known_from_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
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
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
    scope_id: usize,
    module: &str,
    start: TextSize,
) {
    match module {
        "aws_cdk" => {
            push_binding_event(
                events,
                scope_id,
                "aws_s3",
                start,
                Some(S3BindingKind::S3Module),
            );
            push_binding_event(
                events,
                scope_id,
                "aws_s3_deployment",
                start,
                Some(S3BindingKind::DeploymentModule),
            );
        }
        "aws_cdk.aws_s3" => {
            push_binding_event(
                events,
                scope_id,
                "Bucket",
                start,
                Some(S3BindingKind::Bucket),
            );
            push_binding_event(
                events,
                scope_id,
                "BucketAccessControl",
                start,
                Some(S3BindingKind::BucketAccessControl),
            );
        }
        "aws_cdk.aws_s3_deployment" => {
            push_binding_event(
                events,
                scope_id,
                "BucketDeployment",
                start,
                Some(S3BindingKind::BucketDeployment),
            );
        }
        _ => {}
    }
}

fn known_from_import_kind(module: &str, name: &str) -> Option<S3BindingKind> {
    match (module, name) {
        ("aws_cdk", "aws_s3") => Some(S3BindingKind::S3Module),
        ("aws_cdk", "aws_s3_deployment") => Some(S3BindingKind::DeploymentModule),
        ("aws_cdk.aws_s3", "Bucket") => Some(S3BindingKind::Bucket),
        ("aws_cdk.aws_s3", "BucketAccessControl") => Some(S3BindingKind::BucketAccessControl),
        ("aws_cdk.aws_s3_deployment", "BucketDeployment") => Some(S3BindingKind::BucketDeployment),
        _ => None,
    }
}

fn sort_binding_events(events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>) {
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
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
    scope_id: usize,
    name: &str,
    start: TextSize,
    kind: Option<S3BindingKind>,
) {
    events
        .entry(scope_id)
        .or_default()
        .entry(name.to_string())
        .or_default()
        .push(S3BindingEvent { start, kind });
}

fn record_rebinding_events(
    stmt: &Stmt,
    scopes: &[LexicalScope],
    tracked_names: &HashSet<String>,
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
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

fn has_unknown_keyword_unpack(arguments: &ruff_python_ast::Arguments) -> bool {
    arguments
        .keywords
        .iter()
        .any(|keyword| keyword.arg.is_none() && !matches!(keyword.value, Expr::Dict(_)))
}

fn literal_unpacked_keyword<'a>(
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
        dict.items.iter().find_map(|item| {
            item.key
                .as_ref()
                .and_then(string_literal_text)
                .filter(|key| key == name)
                .map(|_| &item.value)
        })
    })
}

// --- python:S6252 — S3 buckets should have versioning enabled -------------------

const OMITTED_VERSIONING: &str =
    "Omitting the \"versioned\" argument disables S3 bucket versioning. Make sure it is safe here.";
const DISABLED_VERSIONING: &str = "Make sure an unversioned S3 bucket is safe here.";
const LEGACY_MESSAGE: &str = "Enable versioning for this S3 bucket.";
fn check_s3_bucket_call(
    bindings: Option<&S3Bindings>,
    call: &ruff_python_ast::ExprCall,
    at: TextSize,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) -> bool {
    let Some(bindings) = bindings else {
        return false;
    };
    if !bindings.is_s3_bucket_constructor(&call.func, at) {
        return false;
    }
    if has_unknown_keyword_unpack(&call.arguments) {
        return true;
    }
    let versioned = keyword_value(&call.arguments, "versioned")
        .or_else(|| literal_unpacked_keyword(&call.arguments, "versioned"));
    let Some(versioned) = versioned else {
        issues.push(issue_at(
            "python:S6252",
            OMITTED_VERSIONING,
            call.func.range(),
            index,
            source,
        ));
        return true;
    };
    if is_false_literal(versioned) {
        issues.push(issue_at(
            "python:S6252",
            DISABLED_VERSIONING,
            keyword_range(&call.arguments, "versioned").unwrap_or_else(|| versioned.range()),
            index,
            source,
        ));
    }
    true
}

pub(crate) fn check_s6252_s3_versioning(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let bindings = file_ctx
        .has_aws_cdk_import
        .then(|| S3Bindings::collect(file_ctx));
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let at = call.range().start();
        if check_s3_bucket_call(bindings.as_ref(), call, at, index, source, &mut issues) {
            continue;
        }
        if called_name(&call.func) == Some("put_bucket_versioning")
            && !has_keyword(&call.arguments, "VersioningConfiguration")
        {
            issues.push(issue_at(
                "python:S6252",
                LEGACY_MESSAGE,
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6252_requires_versioning_on_cdk_buckets() {
        let flagged =
            "from aws_cdk import aws_s3 as s3\ns3.Bucket(self, \"bucket\", versioned=False)\n";
        assert_eq!(findings(&scan(flagged), "python:S6252").len(), 1);
        let safe =
            "from aws_cdk import aws_s3 as s3\ns3.Bucket(self, \"bucket\", versioned=True)\n";
        assert!(findings(&scan(safe), "python:S6252").is_empty());
        let unknown = concat!(
            "from aws_cdk import aws_s3 as s3\n",
            "def configured_bucket(versioning):\n",
            "    return s3.Bucket(self, \"bucket\", versioned=versioning)\n",
        );
        assert!(findings(&scan(unknown), "python:S6252").is_empty());
    }

    #[test]
    fn s6252_requires_trusted_aliases_and_rebinding() {
        let source = concat!(
            "from aws_cdk.aws_s3 import Bucket as S3Bucket\n",
            "S3Bucket(self, \"real\", versioned=False)\n",
            "S3Bucket = LocalBucket\n",
            "S3Bucket(self, \"local\", versioned=False)\n",
            "from aws_cdk import aws_s3 as s3\n",
            "s3.Bucket(self, \"real_again\", versioned=False)\n",
            "s3 = fake_module\n",
            "s3.Bucket(self, \"local_again\", versioned=False)\n",
        );
        assert_eq!(findings(&scan(source), "python:S6252").len(), 2);
        let lookalike =
            "import aws_cdk_fake as s3\ns3.Bucket(self, \"lookalike\", versioned=False)\n";
        assert!(findings(&scan(lookalike), "python:S6252").is_empty());
    }

    #[test]
    fn s6252_preserves_legacy_boto3_versioning_check() {
        assert_eq!(
            findings(
                &scan("s3.put_bucket_versioning(Bucket=\"b\")\n"),
                "python:S6252"
            )
            .len(),
            1
        );
        assert!(findings(
            &scan(
                "s3.put_bucket_versioning(Bucket=\"b\", VersioningConfiguration={\"Status\": \"Enabled\"})\n"
            ),
            "python:S6252"
        )
        .is_empty());
    }
}
