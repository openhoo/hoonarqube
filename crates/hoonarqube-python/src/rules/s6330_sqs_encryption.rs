use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::{
    for_each_stmt_in_scope, is_false_literal, issue_at, keyword_range, keyword_value,
    named_parameters, stmt_store_names, string_literal_text,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, Stmt, StmtFunctionDef, StmtImport, StmtImportFrom};
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
enum SqsBindingKind {
    CdkRoot,
    SqsModule,
    Queue,
    CfnQueue,
    QueueEncryption,
}

#[derive(Clone, Copy)]
struct SqsBindingEvent {
    start: TextSize,
    kind: Option<SqsBindingKind>,
}

#[derive(Default)]
struct SqsBindings {
    module_aliases: HashSet<String>,
    imported_module_roots: HashSet<String>,
    queue_names: HashSet<String>,
    cfn_queue_names: HashSet<String>,
    queue_encryption_names: HashSet<String>,
    events: HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>,
    scopes: Vec<LexicalScope>,
}

impl SqsBindings {
    fn collect(file_ctx: &FileContext<'_>) -> Self {
        let mut bindings = Self {
            scopes: lexical_scopes(file_ctx),
            ..Self::default()
        };
        collect_import_bindings(&mut bindings, &file_ctx.imports);
        collect_import_events(&mut bindings.events, &bindings.scopes, &file_ctx.imports);
        let tracked_names = bindings.tracked_names();
        collect_function_bindings(&mut bindings, &file_ctx.functions, &tracked_names);
        collect_rebinding_bindings(&mut bindings, &file_ctx.stmts, &tracked_names);
        sort_binding_events(&mut bindings.events);
        bindings
    }

    fn record_tracked_event(
        &mut self,
        scope_id: usize,
        name: &str,
        start: TextSize,
        tracked_names: &HashSet<String>,
    ) {
        if tracked_names.contains(name) {
            push_binding_event(&mut self.events, scope_id, name, start, None);
        }
    }
    fn tracked_names(&self) -> HashSet<String> {
        self.module_aliases
            .iter()
            .chain(&self.imported_module_roots)
            .chain(&self.queue_names)
            .chain(&self.cfn_queue_names)
            .chain(&self.queue_encryption_names)
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

    fn binding_at(&self, name: &str, at: TextSize) -> Option<SqsBindingKind> {
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
        kind: SqsBindingKind,
        at: TextSize,
    ) -> bool {
        match function {
            Expr::Name(name) => {
                imported_names.contains(name.id.as_str())
                    && self.binding_at(name.id.as_str(), at) == Some(kind)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == attribute_name
                    && self.is_sqs_module(&attribute.value, at)
            }
            _ => false,
        }
    }

    fn is_queue(&self, function: &Expr, at: TextSize) -> bool {
        self.is_constructor(
            function,
            "Queue",
            &self.queue_names,
            SqsBindingKind::Queue,
            at,
        )
    }

    fn is_cfn_queue(&self, function: &Expr, at: TextSize) -> bool {
        self.is_constructor(
            function,
            "CfnQueue",
            &self.cfn_queue_names,
            SqsBindingKind::CfnQueue,
            at,
        )
    }

    fn is_unencrypted(&self, value: &Expr, at: TextSize) -> bool {
        let Expr::Attribute(attribute) = value else {
            return false;
        };
        attribute.attr.as_str() == "UNENCRYPTED"
            && match attribute.value.as_ref() {
                Expr::Name(name) => {
                    self.queue_encryption_names.contains(name.id.as_str())
                        && self.binding_at(name.id.as_str(), at)
                            == Some(SqsBindingKind::QueueEncryption)
                }
                Expr::Attribute(parent) => {
                    parent.attr.as_str() == "QueueEncryption"
                        && self.is_sqs_module(&parent.value, at)
                }
                _ => false,
            }
    }
    fn is_sqs_module(&self, value: &Expr, at: TextSize) -> bool {
        match value {
            Expr::Name(name) => {
                self.module_aliases.contains(name.id.as_str())
                    && self.binding_at(name.id.as_str(), at) == Some(SqsBindingKind::SqsModule)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == "aws_sqs"
                    && matches!(
                        attribute.value.as_ref(),
                        Expr::Name(name)
                            if self.imported_module_roots.contains(name.id.as_str())
                                && self.binding_at(name.id.as_str(), at)
                                    == Some(SqsBindingKind::CdkRoot)
                    )
            }
            _ => false,
        }
    }
}

fn collect_function_bindings(
    bindings: &mut SqsBindings,
    functions: &[&StmtFunctionDef],
    tracked_names: &HashSet<String>,
) {
    for function in functions {
        let function = *function;
        let Some(range) = body_range(function.body.as_slice()) else {
            continue;
        };
        let scope_id = scope_for_range(&bindings.scopes, range);
        let activation = bindings.scopes[scope_id].range.start();
        collect_function_parameter_bindings(
            bindings,
            function,
            scope_id,
            activation,
            tracked_names,
        );
        collect_function_store_bindings(bindings, function, scope_id, activation, tracked_names);
    }
}

fn collect_function_parameter_bindings(
    bindings: &mut SqsBindings,
    function: &StmtFunctionDef,
    scope_id: usize,
    activation: TextSize,
    tracked_names: &HashSet<String>,
) {
    for parameter in named_parameters(&function.parameters) {
        bindings.record_tracked_event(
            scope_id,
            parameter.parameter.name.as_str(),
            activation,
            tracked_names,
        );
    }
    for parameter in [
        function.parameters.vararg.as_deref(),
        function.parameters.kwarg.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        bindings.record_tracked_event(scope_id, parameter.name.as_str(), activation, tracked_names);
    }
}

fn collect_function_store_bindings(
    bindings: &mut SqsBindings,
    function: &StmtFunctionDef,
    scope_id: usize,
    activation: TextSize,
    tracked_names: &HashSet<String>,
) {
    for_each_stmt_in_scope(&function.body, &mut |stmt| {
        for name in stmt_store_names(stmt) {
            bindings.record_tracked_event(scope_id, &name, activation, tracked_names);
        }
    });
}

fn collect_rebinding_bindings(
    bindings: &mut SqsBindings,
    statements: &[&Stmt],
    tracked_names: &HashSet<String>,
) {
    for stmt in statements {
        record_rebinding_events(stmt, &bindings.scopes, tracked_names, &mut bindings.events);
    }
}

fn collect_import_bindings(bindings: &mut SqsBindings, imports: &[AnyImport<'_>]) {
    for import in imports {
        match import {
            AnyImport::Plain(import) => collect_plain_import_bindings(bindings, import),
            AnyImport::From(import) => collect_from_import_bindings(bindings, import),
        }
    }
}

fn collect_plain_import_bindings(bindings: &mut SqsBindings, import: &StmtImport) {
    for alias in &import.names {
        collect_plain_import_alias_binding(bindings, alias);
    }
}

fn collect_plain_import_alias_binding(bindings: &mut SqsBindings, alias: &ruff_python_ast::Alias) {
    match alias.name.as_str() {
        "aws_cdk" => {
            bindings
                .imported_module_roots
                .insert(alias.asname.as_deref().unwrap_or("aws_cdk").to_string());
        }
        "aws_cdk.aws_sqs" => {
            if let Some(asname) = alias.asname.as_deref() {
                bindings.module_aliases.insert(asname.to_string());
            } else {
                bindings.imported_module_roots.insert("aws_cdk".to_string());
            }
        }
        _ => {}
    }
}

fn collect_from_import_bindings(bindings: &mut SqsBindings, import: &StmtImportFrom) {
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
        "aws_cdk.aws_sqs" => collect_sqs_from_bindings(bindings, &import.names),
        _ => {}
    }
}

fn collect_cdk_module_bindings(bindings: &mut SqsBindings, names: &[ruff_python_ast::Alias]) {
    for alias in names {
        if matches!(alias.name.as_str(), "aws_sqs" | "*") {
            bindings
                .module_aliases
                .insert(alias.asname.as_deref().unwrap_or("aws_sqs").to_string());
        }
    }
}

fn collect_sqs_from_bindings(bindings: &mut SqsBindings, names: &[ruff_python_ast::Alias]) {
    for alias in names {
        if alias.name.as_str() == "*" {
            bindings.queue_names.insert("Queue".to_string());
            bindings.cfn_queue_names.insert("CfnQueue".to_string());
            bindings
                .queue_encryption_names
                .insert("QueueEncryption".to_string());
            continue;
        }
        let local = alias
            .asname
            .as_deref()
            .unwrap_or(alias.name.as_str())
            .to_string();
        match alias.name.as_str() {
            "Queue" => {
                bindings.queue_names.insert(local);
            }
            "CfnQueue" => {
                bindings.cfn_queue_names.insert(local);
            }
            "QueueEncryption" => {
                bindings.queue_encryption_names.insert(local);
            }
            _ => {}
        }
    }
}

fn collect_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>,
    scopes: &[LexicalScope],
    imports: &[AnyImport<'_>],
) {
    for import in imports {
        let import_range = match import {
            AnyImport::Plain(import) => import.range(),
            AnyImport::From(import) => import.range(),
        };
        let scope_id = scope_for_range(scopes, import_range);
        match import {
            AnyImport::Plain(import) => {
                collect_plain_import_events(events, scope_id, import_range.end(), import);
            }
            AnyImport::From(import) => {
                collect_from_import_events(events, scope_id, import_range.end(), import);
            }
        }
    }
}

fn collect_plain_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>,
    scope_id: usize,
    import_end: TextSize,
    import: &StmtImport,
) {
    for alias in &import.names {
        let local = alias.asname.as_deref().unwrap_or_else(|| {
            alias
                .name
                .as_str()
                .split('.')
                .next()
                .unwrap_or(alias.name.as_str())
        });
        push_binding_event(
            events,
            scope_id,
            local,
            import_end,
            sqs_plain_import_event_kind(alias),
        );
    }
}

fn sqs_plain_import_event_kind(alias: &ruff_python_ast::Alias) -> Option<SqsBindingKind> {
    match alias.name.as_str() {
        "aws_cdk.aws_sqs" if alias.asname.is_some() => Some(SqsBindingKind::SqsModule),
        "aws_cdk" | "aws_cdk.aws_sqs" => Some(SqsBindingKind::CdkRoot),
        _ => None,
    }
}

fn collect_from_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>,
    scope_id: usize,
    import_end: TextSize,
    import: &StmtImportFrom,
) {
    for alias in &import.names {
        collect_from_import_alias_events(events, scope_id, import_end, import, alias);
    }
}

fn collect_from_import_alias_events(
    events: &mut HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>,
    scope_id: usize,
    import_end: TextSize,
    import: &StmtImportFrom,
    alias: &ruff_python_ast::Alias,
) {
    if alias.name.as_str() == "*" {
        push_sqs_wildcard_import_events(events, scope_id, import_end, import);
        return;
    }
    let local = alias.asname.as_deref().unwrap_or(alias.name.as_str());
    push_binding_event(
        events,
        scope_id,
        local,
        import_end,
        sqs_from_import_event_kind(import, alias),
    );
}

fn push_sqs_wildcard_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>,
    scope_id: usize,
    import_end: TextSize,
    import: &StmtImportFrom,
) {
    let module = import
        .module
        .as_ref()
        .map(ruff_python_ast::Identifier::as_str);
    let names: &[(&str, Option<SqsBindingKind>)] = match (import.level, module) {
        (0, Some("aws_cdk")) => [("aws_sqs", Some(SqsBindingKind::SqsModule))].as_slice(),
        (0, Some("aws_cdk.aws_sqs")) => &[
            ("Queue", Some(SqsBindingKind::Queue)),
            ("CfnQueue", Some(SqsBindingKind::CfnQueue)),
            ("QueueEncryption", Some(SqsBindingKind::QueueEncryption)),
        ],
        _ => &[
            ("aws_sqs", None),
            ("Queue", None),
            ("CfnQueue", None),
            ("QueueEncryption", None),
        ],
    };
    for &(name, kind) in names {
        push_binding_event(events, scope_id, name, import_end, kind);
    }
}

fn sqs_from_import_event_kind(
    import: &StmtImportFrom,
    alias: &ruff_python_ast::Alias,
) -> Option<SqsBindingKind> {
    match (
        import.level,
        import
            .module
            .as_ref()
            .map(ruff_python_ast::Identifier::as_str),
        alias.name.as_str(),
    ) {
        (0, Some("aws_cdk"), "aws_sqs") => Some(SqsBindingKind::SqsModule),
        (0, Some("aws_cdk.aws_sqs"), "Queue") => Some(SqsBindingKind::Queue),
        (0, Some("aws_cdk.aws_sqs"), "CfnQueue") => Some(SqsBindingKind::CfnQueue),
        (0, Some("aws_cdk.aws_sqs"), "QueueEncryption") => Some(SqsBindingKind::QueueEncryption),
        _ => None,
    }
}

fn sort_binding_events(events: &mut HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>) {
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
    events: &mut HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>,
    scope_id: usize,
    name: &str,
    start: TextSize,
    kind: Option<SqsBindingKind>,
) {
    events
        .entry(scope_id)
        .or_default()
        .entry(name.to_string())
        .or_default()
        .push(SqsBindingEvent { start, kind });
}

fn record_rebinding_events(
    stmt: &Stmt,
    scopes: &[LexicalScope],
    tracked_names: &HashSet<String>,
    events: &mut HashMap<usize, HashMap<String, Vec<SqsBindingEvent>>>,
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

// --- python:S6330 — SQS queues encrypted ----------------------------------------

const OMITTED_KMS: &str =
    "Omitting \"kms_master_key_id\" disables SQS queues encryption. Make sure it is safe here.";
const DISABLED_SSE: &str = "Setting \"sqs_managed_sse_enabled\" to \"false\" disables SQS queues encryption. Make sure it is safe here.";
const DISABLED_QUEUE_ENCRYPTION: &str = "Setting \"encryption\" to \"QueueEncryption.UNENCRYPTED\" disables SQS queues encryption. Make sure it is safe here.";

pub(crate) fn check_s6330_sqs_encryption(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let Some(bindings) = file_ctx
        .has_aws_cdk_import
        .then(|| SqsBindings::collect(file_ctx))
    else {
        return Vec::new();
    };
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let at = call.range().start();
        if has_unknown_keyword_unpack(&call.arguments) {
            continue;
        }
        if bindings.is_cfn_queue(&call.func, at) {
            check_cfn_queue_call(call, index, source, &mut issues);
            continue;
        }
        if bindings.is_queue(&call.func, at) {
            check_queue_call(&bindings, call, at, index, source, &mut issues);
        }
    }
    issues
}

fn check_cfn_queue_call(call: &ExprCall, index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    let has_kms_key = keyword_value(&call.arguments, "kms_master_key_id")
        .or_else(|| literal_unpacked_keyword(&call.arguments, "kms_master_key_id"))
        .is_some();
    let managed_sse = keyword_value(&call.arguments, "sqs_managed_sse_enabled")
        .or_else(|| literal_unpacked_keyword(&call.arguments, "sqs_managed_sse_enabled"));
    let Some(value) = managed_sse else {
        if !has_kms_key {
            issues.push(issue_at(
                "python:S6330",
                OMITTED_KMS,
                call.func.range(),
                index,
                source,
            ));
        }
        return;
    };
    if is_false_literal(value) && !has_kms_key {
        issues.push(issue_at(
            "python:S6330",
            DISABLED_SSE,
            keyword_range(&call.arguments, "sqs_managed_sse_enabled")
                .unwrap_or_else(|| value.range()),
            index,
            source,
        ));
    }
}

fn check_queue_call(
    bindings: &SqsBindings,
    call: &ExprCall,
    at: TextSize,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let encryption = keyword_value(&call.arguments, "encryption")
        .or_else(|| literal_unpacked_keyword(&call.arguments, "encryption"));
    let has_kms_key = keyword_value(&call.arguments, "kms_master_key_id")
        .or_else(|| literal_unpacked_keyword(&call.arguments, "kms_master_key_id"))
        .is_some();
    let Some(encryption) = encryption else {
        if !has_kms_key {
            issues.push(issue_at(
                "python:S6330",
                OMITTED_KMS,
                call.func.range(),
                index,
                source,
            ));
        }
        return;
    };
    if bindings.is_unencrypted(encryption, at) {
        issues.push(issue_at(
            "python:S6330",
            DISABLED_QUEUE_ENCRYPTION,
            keyword_range(&call.arguments, "encryption").unwrap_or_else(|| encryption.range()),
            index,
            source,
        ));
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6330_flags_disabled_sse_but_not_safe_or_unknown_values() {
        let attack = "from aws_cdk import aws_sqs as sqs\nsqs.CfnQueue(self, \"example\", sqs_managed_sse_enabled=False)\n";
        assert_eq!(findings(&scan(attack), "python:S6330").len(), 1);
        let safe = "from aws_cdk import aws_sqs as sqs\nsqs.CfnQueue(self, \"example\", sqs_managed_sse_enabled=True)\n";
        assert!(findings(&scan(safe), "python:S6330").is_empty());
        let unknown = concat!(
            "from aws_cdk import aws_sqs as sqs\n",
            "def make_queue(enabled):\n",
            "    return sqs.CfnQueue(self, \"configured\", sqs_managed_sse_enabled=enabled)\n",
        );
        assert!(findings(&scan(unknown), "python:S6330").is_empty());
        let kms = "from aws_cdk import aws_sqs as sqs\nsqs.CfnQueue(self, \"example\", kms_master_key_id=\"alias/jobs\")\n";
        assert!(findings(&scan(kms), "python:S6330").is_empty());
        let kms_with_disabled_managed_sse = concat!(
            "from aws_cdk import aws_sqs as sqs\n",
            "sqs.CfnQueue(self, \"kms\", sqs_managed_sse_enabled=False, kms_master_key_id=\"alias/jobs\")\n",
        );
        assert!(findings(&scan(kms_with_disabled_managed_sse), "python:S6330").is_empty());
        let high_level = concat!(
            "from aws_cdk import aws_sqs as sqs\n",
            "sqs.Queue(self, \"safe\", encryption=sqs.QueueEncryption.SQS_MANAGED)\n",
            "sqs.Queue(self, \"unsafe\", encryption=sqs.QueueEncryption.UNENCRYPTED)\n",
        );
        assert_eq!(findings(&scan(high_level), "python:S6330").len(), 1);
    }

    #[test]
    fn s6330_requires_trusted_queue_provenance() {
        let source = concat!(
            "from aws_cdk.aws_sqs import CfnQueue as QueueResource\n",
            "QueueResource(self, \"real\", sqs_managed_sse_enabled=False)\n",
            "QueueResource = LocalQueue\n",
            "QueueResource(self, \"local\", sqs_managed_sse_enabled=False)\n",
            "import aws_cdk_fake.aws_sqs as fake_sqs\n",
            "fake_sqs.CfnQueue(self, \"lookalike\", sqs_managed_sse_enabled=False)\n",
        );
        assert_eq!(findings(&scan(source), "python:S6330").len(), 1);
    }
}
