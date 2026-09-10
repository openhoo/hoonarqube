use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::{
    call_source_text, called_name, for_each_stmt_in_scope, has_keyword, is_false_literal, issue_at,
    keyword_range, keyword_value, named_parameters, stmt_store_names, string_literal_text,
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
enum Ec2BindingKind {
    CdkRoot,
    Ec2Module,
    Volume,
    Instance,
    SubnetSelection,
    SubnetType,
}

#[derive(Clone, Copy)]
struct Ec2BindingEvent {
    start: TextSize,
    kind: Option<Ec2BindingKind>,
}

#[derive(Default)]
pub(super) struct Ec2Bindings {
    module_aliases: HashSet<String>,
    imported_module_roots: HashSet<String>,
    volume_names: HashSet<String>,
    instance_names: HashSet<String>,
    subnet_selection_names: HashSet<String>,
    subnet_type_names: HashSet<String>,
    events: HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>,
    scopes: Vec<LexicalScope>,
}

impl Ec2Bindings {
    pub(super) fn collect(file_ctx: &FileContext<'_>) -> Self {
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
            .chain(&self.volume_names)
            .chain(&self.instance_names)
            .chain(&self.subnet_selection_names)
            .chain(&self.subnet_type_names)
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

    fn binding_at(&self, name: &str, at: TextSize) -> Option<Ec2BindingKind> {
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

    pub(super) fn is_volume_constructor(&self, function: &Expr, at: TextSize) -> bool {
        self.is_named_constructor(
            function,
            "Volume",
            &self.volume_names,
            Ec2BindingKind::Volume,
            at,
        )
    }

    pub(super) fn is_instance_constructor(&self, function: &Expr, at: TextSize) -> bool {
        self.is_named_constructor(
            function,
            "Instance",
            &self.instance_names,
            Ec2BindingKind::Instance,
            at,
        )
    }

    pub(super) fn is_subnet_selection_constructor(&self, function: &Expr, at: TextSize) -> bool {
        self.is_named_constructor(
            function,
            "SubnetSelection",
            &self.subnet_selection_names,
            Ec2BindingKind::SubnetSelection,
            at,
        )
    }

    fn is_named_constructor(
        &self,
        function: &Expr,
        attribute_name: &str,
        imported_names: &HashSet<String>,
        kind: Ec2BindingKind,
        at: TextSize,
    ) -> bool {
        match function {
            Expr::Name(name) => {
                imported_names.contains(name.id.as_str())
                    && self.binding_at(name.id.as_str(), at) == Some(kind)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == attribute_name
                    && self.is_ec2_module(&attribute.value, at)
            }
            _ => false,
        }
    }

    pub(super) fn is_public_subnet_type(&self, value: &Expr, at: TextSize) -> bool {
        let Expr::Attribute(public) = value else {
            return false;
        };
        if public.attr.as_str() != "PUBLIC" {
            return false;
        }
        match public.value.as_ref() {
            Expr::Name(name) => {
                self.subnet_type_names.contains(name.id.as_str())
                    && self.binding_at(name.id.as_str(), at) == Some(Ec2BindingKind::SubnetType)
            }
            Expr::Attribute(subnet_type) => {
                subnet_type.attr.as_str() == "SubnetType"
                    && self.is_ec2_module(&subnet_type.value, at)
            }
            _ => false,
        }
    }

    fn is_ec2_module(&self, value: &Expr, at: TextSize) -> bool {
        match value {
            Expr::Name(name) => {
                self.module_aliases.contains(name.id.as_str())
                    && self.binding_at(name.id.as_str(), at) == Some(Ec2BindingKind::Ec2Module)
            }
            Expr::Attribute(attribute) => {
                attribute.attr.as_str() == "aws_ec2"
                    && matches!(
                        attribute.value.as_ref(),
                        Expr::Name(name)
                            if self.imported_module_roots.contains(name.id.as_str())
                                && self.binding_at(name.id.as_str(), at)
                                    == Some(Ec2BindingKind::CdkRoot)
                    )
            }
            _ => false,
        }
    }
}

fn collect_function_bindings(
    bindings: &mut Ec2Bindings,
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
    bindings: &mut Ec2Bindings,
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
    bindings: &mut Ec2Bindings,
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
    bindings: &mut Ec2Bindings,
    statements: &[&Stmt],
    tracked_names: &HashSet<String>,
) {
    for stmt in statements {
        record_rebinding_events(stmt, &bindings.scopes, tracked_names, &mut bindings.events);
    }
}

fn collect_import_bindings(bindings: &mut Ec2Bindings, imports: &[AnyImport<'_>]) {
    for import in imports {
        match import {
            AnyImport::Plain(import) => collect_plain_import_bindings(bindings, import),
            AnyImport::From(import) => collect_from_import_bindings(bindings, import),
        }
    }
}

fn collect_plain_import_bindings(bindings: &mut Ec2Bindings, import: &StmtImport) {
    for alias in &import.names {
        collect_plain_import_alias_binding(bindings, alias);
    }
}

fn collect_plain_import_alias_binding(bindings: &mut Ec2Bindings, alias: &ruff_python_ast::Alias) {
    match alias.name.as_str() {
        "aws_cdk" => {
            bindings
                .imported_module_roots
                .insert(alias.asname.as_deref().unwrap_or("aws_cdk").to_string());
        }
        "aws_cdk.aws_ec2" => {
            if let Some(asname) = alias.asname.as_deref() {
                bindings.module_aliases.insert(asname.to_string());
            } else {
                bindings.imported_module_roots.insert("aws_cdk".to_string());
            }
        }
        _ => {}
    }
}

fn collect_from_import_bindings(bindings: &mut Ec2Bindings, import: &StmtImportFrom) {
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
        "aws_cdk.aws_ec2" => collect_ec2_from_bindings(bindings, &import.names),
        _ => {}
    }
}

fn collect_cdk_module_bindings(bindings: &mut Ec2Bindings, names: &[ruff_python_ast::Alias]) {
    for alias in names {
        if matches!(alias.name.as_str(), "aws_ec2" | "*") {
            bindings
                .module_aliases
                .insert(alias.asname.as_deref().unwrap_or("aws_ec2").to_string());
        }
    }
}

fn collect_ec2_from_bindings(bindings: &mut Ec2Bindings, names: &[ruff_python_ast::Alias]) {
    for alias in names {
        if alias.name.as_str() == "*" {
            bindings.volume_names.insert("Volume".to_string());
            bindings.instance_names.insert("Instance".to_string());
            bindings
                .subnet_selection_names
                .insert("SubnetSelection".to_string());
            bindings.subnet_type_names.insert("SubnetType".to_string());
            continue;
        }
        let local = alias
            .asname
            .as_deref()
            .unwrap_or(alias.name.as_str())
            .to_string();
        match alias.name.as_str() {
            "Volume" => {
                bindings.volume_names.insert(local);
            }
            "Instance" => {
                bindings.instance_names.insert(local);
            }
            "SubnetSelection" => {
                bindings.subnet_selection_names.insert(local);
            }
            "SubnetType" => {
                bindings.subnet_type_names.insert(local);
            }
            _ => {}
        }
    }
}

fn collect_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>,
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
    events: &mut HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>,
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
            ec2_plain_import_event_kind(alias),
        );
    }
}

fn ec2_plain_import_event_kind(alias: &ruff_python_ast::Alias) -> Option<Ec2BindingKind> {
    match alias.name.as_str() {
        "aws_cdk.aws_ec2" if alias.asname.is_some() => Some(Ec2BindingKind::Ec2Module),
        "aws_cdk" | "aws_cdk.aws_ec2" => Some(Ec2BindingKind::CdkRoot),
        _ => None,
    }
}

fn collect_from_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>,
    scope_id: usize,
    import_end: TextSize,
    import: &StmtImportFrom,
) {
    for alias in &import.names {
        collect_from_import_alias_events(events, scope_id, import_end, import, alias);
    }
}

fn collect_from_import_alias_events(
    events: &mut HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>,
    scope_id: usize,
    import_end: TextSize,
    import: &StmtImportFrom,
    alias: &ruff_python_ast::Alias,
) {
    if alias.name.as_str() == "*" {
        push_ec2_wildcard_import_events(events, scope_id, import_end, import);
        return;
    }
    let local = alias.asname.as_deref().unwrap_or(alias.name.as_str());
    push_binding_event(
        events,
        scope_id,
        local,
        import_end,
        ec2_from_import_event_kind(import, alias),
    );
}

fn push_ec2_wildcard_import_events(
    events: &mut HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>,
    scope_id: usize,
    import_end: TextSize,
    import: &StmtImportFrom,
) {
    let module = import
        .module
        .as_ref()
        .map(ruff_python_ast::Identifier::as_str);
    let names: &[(&str, Option<Ec2BindingKind>)] = match (import.level, module) {
        (0, Some("aws_cdk")) => [("aws_ec2", Some(Ec2BindingKind::Ec2Module))].as_slice(),
        (0, Some("aws_cdk.aws_ec2")) => &[
            ("Volume", Some(Ec2BindingKind::Volume)),
            ("Instance", Some(Ec2BindingKind::Instance)),
            ("SubnetSelection", Some(Ec2BindingKind::SubnetSelection)),
            ("SubnetType", Some(Ec2BindingKind::SubnetType)),
        ],
        _ => &[
            ("aws_ec2", None),
            ("Volume", None),
            ("Instance", None),
            ("SubnetSelection", None),
            ("SubnetType", None),
        ],
    };
    for &(name, kind) in names {
        push_binding_event(events, scope_id, name, import_end, kind);
    }
}

fn ec2_from_import_event_kind(
    import: &StmtImportFrom,
    alias: &ruff_python_ast::Alias,
) -> Option<Ec2BindingKind> {
    match (
        import.level,
        import
            .module
            .as_ref()
            .map(ruff_python_ast::Identifier::as_str),
        alias.name.as_str(),
    ) {
        (0, Some("aws_cdk"), "aws_ec2") => Some(Ec2BindingKind::Ec2Module),
        (0, Some("aws_cdk.aws_ec2"), "Volume") => Some(Ec2BindingKind::Volume),
        (0, Some("aws_cdk.aws_ec2"), "Instance") => Some(Ec2BindingKind::Instance),
        (0, Some("aws_cdk.aws_ec2"), "SubnetSelection") => Some(Ec2BindingKind::SubnetSelection),
        (0, Some("aws_cdk.aws_ec2"), "SubnetType") => Some(Ec2BindingKind::SubnetType),
        _ => None,
    }
}

fn sort_binding_events(events: &mut HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>) {
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
    events: &mut HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>,
    scope_id: usize,
    name: &str,
    start: TextSize,
    kind: Option<Ec2BindingKind>,
) {
    events
        .entry(scope_id)
        .or_default()
        .entry(name.to_string())
        .or_default()
        .push(Ec2BindingEvent { start, kind });
}

fn record_rebinding_events(
    stmt: &Stmt,
    scopes: &[LexicalScope],
    tracked_names: &HashSet<String>,
    events: &mut HashMap<usize, HashMap<String, Vec<Ec2BindingEvent>>>,
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

// --- python:S6275 — EBS volumes encrypted ----------------------------------------

const OMITTED_ENCRYPTION: &str =
    "Omitting \"encrypted\" disables volumes encryption. Make sure it is safe here.";
const DISABLED_ENCRYPTION: &str = "Make sure that using unencrypted volumes is safe here.";
const LEGACY_MESSAGE: &str = "Encrypt this EBS volume at rest.";

pub(crate) fn check_s6275_ebs_encryption(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let bindings = file_ctx
        .has_aws_cdk_import
        .then(|| Ec2Bindings::collect(file_ctx));
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let at = call.range().start();
        if check_volume_call(bindings.as_ref(), call, at, index, source, &mut issues) {
            continue;
        }
        if is_legacy_unencrypted(call, source) {
            issues.push(issue_at(
                "python:S6275",
                LEGACY_MESSAGE,
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn check_volume_call(
    bindings: Option<&Ec2Bindings>,
    call: &ExprCall,
    at: TextSize,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) -> bool {
    let Some(bindings) = bindings else {
        return false;
    };
    if !bindings.is_volume_constructor(&call.func, at) {
        return false;
    }
    if has_unknown_keyword_unpack(&call.arguments) {
        return true;
    }
    let encrypted = keyword_value(&call.arguments, "encrypted")
        .or_else(|| literal_unpacked_keyword(&call.arguments, "encrypted"));
    let (message, range) = match encrypted {
        None => (OMITTED_ENCRYPTION, call.func.range()),
        Some(value) if is_false_literal(value) => (
            DISABLED_ENCRYPTION,
            keyword_range(&call.arguments, "encrypted").unwrap_or_else(|| value.range()),
        ),
        Some(_) => return true,
    };
    issues.push(issue_at("python:S6275", message, range, index, source));
    true
}

fn is_legacy_unencrypted(call: &ExprCall, source: &str) -> bool {
    match called_name(&call.func) {
        Some("create_volume") => {
            !has_keyword(&call.arguments, "Encrypted")
                || keyword_value(&call.arguments, "Encrypted").is_some_and(is_false_literal)
        }
        Some("run_instances") => {
            has_keyword(&call.arguments, "BlockDeviceMappings")
                && !call_source_text(call, source).contains("Encrypted")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6275_flags_unencrypted_cdk_volumes_and_preserves_legacy_api() {
        let flagged = concat!(
            "from aws_cdk.aws_ec2 import Volume\n",
            "Volume(self, \"volume\", availability_zone=\"eu-west-1a\", size=Size.gibibytes(1))\n",
            "Volume(self, \"plain\", encrypted=False)\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6275").len(), 2);
        let safe = "from aws_cdk.aws_ec2 import Volume\nVolume(self, \"volume\", encrypted=True)\n";
        assert!(findings(&scan(safe), "python:S6275").is_empty());
        let unknown = concat!(
            "from aws_cdk.aws_ec2 import Volume\n",
            "def make_volume(encrypted):\n",
            "    return Volume(self, \"runtime\", encrypted=encrypted)\n",
        );
        assert!(findings(&scan(unknown), "python:S6275").is_empty());
        let legacy = concat!(
            "ec2.create_volume(Size=8, AvailabilityZone=\"us-east-1a\")\n",
            "ec2.create_volume(Size=8, Encrypted=False)\n",
            "ec2.run_instances(ImageId=\"ami\", BlockDeviceMappings=[{\"DeviceName\": \"/dev/sda\"}])\n",
        );
        assert_eq!(findings(&scan(legacy), "python:S6275").len(), 3);
    }

    #[test]
    fn s6275_requires_trusted_volume_provenance() {
        let source = concat!(
            "from aws_cdk.aws_ec2 import Volume as EbsVolume\n",
            "EbsVolume(self, \"real\", encrypted=False)\n",
            "EbsVolume = LocalVolume\n",
            "EbsVolume(self, \"local\", encrypted=False)\n",
            "import aws_cdk_fake.aws_ec2 as fake_ec2\n",
            "fake_ec2.Volume(self, \"lookalike\", encrypted=False)\n",
        );
        assert_eq!(findings(&scan(source), "python:S6275").len(), 1);
    }
}
