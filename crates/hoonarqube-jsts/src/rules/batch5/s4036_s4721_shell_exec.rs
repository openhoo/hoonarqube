use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::shared::argument_expression;
use crate::support::{RuleScope, member_object, unparenthesized};
use oxc_ast::AstKind;
use oxc_ast::ast::{
    BindingPattern, CallExpression, Expression, MemberExpression, ModuleExportName, PropertyKey,
};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::GetSpan;
use oxc_syntax::reference::ReferenceId;
use std::collections::HashMap;

/// Node's child-process entry points that are relevant to the shell and PATH
/// rules. Keeping the API identity separate from the binding kind lets the
/// resolver distinguish a namespace object from a function alias.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessApi {
    Exec,
    ExecSync,
    ExecFile,
    ExecFileSync,
    Spawn,
    SpawnSync,
}

impl ProcessApi {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "exec" => Some(Self::Exec),
            "execSync" => Some(Self::ExecSync),
            "execFile" => Some(Self::ExecFile),
            "execFileSync" => Some(Self::ExecFileSync),
            "spawn" => Some(Self::Spawn),
            "spawnSync" => Some(Self::SpawnSync),
            _ => None,
        }
    }

    fn is_shell_exec(self) -> bool {
        matches!(self, Self::Exec | Self::ExecSync)
    }
}

/// The two namespace shapes exposed by the Node child-process modules, or a
/// function imported/destructured from one of them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessBindingKind {
    ChildProcess,
    Promises,
    Function(ProcessApi),
}

impl ProcessBindingKind {
    fn function(self) -> Option<ProcessApi> {
        match self {
            Self::Function(api) => Some(api),
            Self::ChildProcess | Self::Promises => None,
        }
    }
}

#[derive(Clone, Copy)]
enum RootSource<'a> {
    Identifier {
        reference_id: Option<ReferenceId>,
        at: u32,
    },
    Require {
        module: &'a str,
        require_reference: Option<ReferenceId>,
    },
}

#[derive(Clone, Copy)]
enum MemberPath<'a> {
    Direct(&'a str),
    Promises(&'a str),
}

#[derive(Clone, Copy)]
enum BindingSource<'a> {
    Root(RootSource<'a>),
    Member {
        root: RootSource<'a>,
        path: MemberPath<'a>,
    },
    Unknown,
}

#[derive(Clone, Copy)]
enum PatternSelection<'a> {
    Whole,
    Property(&'a str),
    PromisesProperty(&'a str),
    Unknown,
}

struct AliasCandidate<'a> {
    symbol: SymbolId,
    source: BindingSource<'a>,
    selection: PatternSelection<'a>,
}

struct BindingState {
    kind: Option<ProcessBindingKind>,
    declaration_end: u32,
    writes: Vec<u32>,
}

/// File-local ownership facts for Node child-process calls.
///
/// OXC semantic analysis supplies the identity of every identifier reference,
/// its declaration, and its writes. This pass only projects module provenance
/// onto those existing symbols; it does not build a second scope model.
pub(crate) struct ProcessBindingResolver {
    reference_symbols: HashMap<ReferenceId, SymbolId>,
    bindings: HashMap<SymbolId, BindingState>,
}

impl ProcessBindingResolver {
    pub(crate) fn new(semantic: Option<&Semantic<'_>>) -> Self {
        let mut resolver = Self {
            reference_symbols: HashMap::new(),
            bindings: HashMap::new(),
        };
        let Some(semantic) = semantic else {
            return resolver;
        };
        let mut candidates = Vec::new();

        for symbol in semantic.scoping().symbol_ids() {
            resolver.initialize_symbol(semantic, symbol, &mut candidates);
        }
        resolver.resolve_aliases(&candidates);
        resolver
    }
    fn initialize_symbol<'a>(
        &mut self,
        semantic: &Semantic<'a>,
        symbol: SymbolId,
        candidates: &mut Vec<AliasCandidate<'a>>,
    ) {
        let writes = semantic
            .scoping()
            .get_resolved_reference_ids(symbol)
            .iter()
            .filter_map(|&reference_id| {
                let reference = semantic.scoping().get_reference(reference_id);
                self.reference_symbols.insert(reference_id, symbol);
                reference
                    .is_write()
                    .then(|| semantic.reference_span(reference).start)
            })
            .collect();
        self.bindings.insert(
            symbol,
            BindingState {
                kind: None,
                declaration_end: semantic.scoping().symbol_span(symbol).end,
                writes,
            },
        );

        let declaration = semantic.symbol_declaration(symbol);
        match declaration.kind() {
            AstKind::ImportSpecifier(_)
            | AstKind::ImportDefaultSpecifier(_)
            | AstKind::ImportNamespaceSpecifier(_) => {
                self.initialize_import_binding(semantic, symbol, declaration.kind());
            }
            AstKind::VariableDeclarator(declarator) => {
                Self::collect_variable_candidate(
                    symbol,
                    &declarator.id,
                    declarator.init.as_ref(),
                    candidates,
                );
            }
            _ => {}
        }
    }

    fn initialize_import_binding<'a>(
        &mut self,
        semantic: &Semantic<'a>,
        symbol: SymbolId,
        declaration: AstKind<'a>,
    ) {
        if let Some(kind) = import_binding_kind(semantic, declaration)
            && let Some(binding) = self.bindings.get_mut(&symbol)
        {
            binding.kind = Some(kind);
        }
    }

    fn collect_variable_candidate<'a>(
        symbol: SymbolId,
        pattern: &BindingPattern<'a>,
        init: Option<&Expression<'a>>,
        candidates: &mut Vec<AliasCandidate<'a>>,
    ) {
        let Some(selection) =
            pattern_selection_for_symbol(pattern, symbol, PatternSelection::Whole)
        else {
            return;
        };
        let Some(init) = init else {
            return;
        };
        let source = binding_source(init);
        if !matches!(source, BindingSource::Unknown) {
            candidates.push(AliasCandidate {
                symbol,
                source,
                selection,
            });
        }
    }

    fn resolve_aliases(&mut self, candidates: &[AliasCandidate<'_>]) {
        // Alias chains can be declared in either order. A bounded fixed point
        // resolves every acyclic chain without guessing unknown values.
        for _ in 0..=candidates.len() {
            let mut changed = false;
            for candidate in candidates {
                if self
                    .bindings
                    .get(&candidate.symbol)
                    .and_then(|binding| binding.kind)
                    .is_some()
                {
                    continue;
                }
                let Some(source) = self.resolve_source(&candidate.source) else {
                    continue;
                };
                let Some(kind) = project_selection(source, candidate.selection) else {
                    continue;
                };
                if let Some(binding) = self.bindings.get_mut(&candidate.symbol) {
                    binding.kind = Some(kind);
                }
                changed = true;
            }
            if !changed {
                break;
            }
        }
    }

    /// Whether `call` resolves to `child_process.exec` or `execSync`.
    pub(crate) fn is_shell_exec(&self, call: &CallExpression<'_>) -> bool {
        self.resolve_call(call)
            .is_some_and(ProcessApi::is_shell_exec)
    }

    /// Whether `call` resolves to one of the child-process APIs whose command
    /// lookup depends on `PATH`.
    pub(crate) fn is_path_lookup(&self, call: &CallExpression<'_>) -> bool {
        self.resolve_call(call).is_some()
    }

    fn resolve_call(&self, call: &CallExpression<'_>) -> Option<ProcessApi> {
        match unparenthesized(&call.callee) {
            Expression::Identifier(identifier) => {
                let symbol = identifier
                    .reference_id
                    .get()
                    .and_then(|reference| self.reference_symbols.get(&reference).copied())?;
                self.kind_at(symbol, call.span().start)
                    .and_then(ProcessBindingKind::function)
            }
            _ => match binding_source(&call.callee) {
                BindingSource::Member { root, path } => self
                    .resolve_root(root, call.span().start)
                    .and_then(|kind| member_kind(kind, path))
                    .and_then(ProcessBindingKind::function),
                BindingSource::Root(_) | BindingSource::Unknown => None,
            },
        }
    }

    fn resolve_source(&self, source: &BindingSource<'_>) -> Option<ProcessBindingKind> {
        let at = source_position(source);
        match *source {
            BindingSource::Root(root) => self.resolve_root(root, at),
            BindingSource::Member { root, path } => self
                .resolve_root(root, at)
                .and_then(|kind| member_kind(kind, path)),
            BindingSource::Unknown => None,
        }
    }

    fn resolve_root(&self, root: RootSource<'_>, at: u32) -> Option<ProcessBindingKind> {
        match root {
            RootSource::Identifier { reference_id, .. } => reference_id
                .and_then(|reference| self.reference_symbols.get(&reference).copied())
                .and_then(|symbol| self.kind_at(symbol, at)),
            RootSource::Require {
                module,
                require_reference,
            } => require_reference
                .filter(|reference| !self.reference_symbols.contains_key(reference))
                .and_then(|_| module_kind(module)),
        }
    }

    fn kind_at(&self, symbol: SymbolId, at: u32) -> Option<ProcessBindingKind> {
        let binding = self.bindings.get(&symbol)?;
        let kind = binding.kind?;
        if binding
            .writes
            .iter()
            .any(|&write| write > binding.declaration_end && write <= at)
        {
            return None;
        }
        Some(kind)
    }
}

fn import_binding_kind<'a>(
    semantic: &Semantic<'a>,
    declaration: AstKind<'a>,
) -> Option<ProcessBindingKind> {
    let AstKind::ImportDeclaration(import) = semantic.nodes().parent_kind(declaration.node_id())
    else {
        return None;
    };
    if import.import_kind.is_type() {
        return None;
    }
    let namespace_kind = module_kind(import.source.value.as_str())?;
    match declaration {
        AstKind::ImportSpecifier(specifier) => {
            if specifier.import_kind.is_type() {
                return None;
            }
            let imported = module_export_name(&specifier.imported);
            named_import_kind(namespace_kind, imported)
        }
        AstKind::ImportDefaultSpecifier(_) | AstKind::ImportNamespaceSpecifier(_) => {
            Some(namespace_kind)
        }
        _ => None,
    }
}

fn named_import_kind(namespace: ProcessBindingKind, imported: &str) -> Option<ProcessBindingKind> {
    match namespace {
        ProcessBindingKind::ChildProcess => {
            if imported == "promises" {
                Some(ProcessBindingKind::Promises)
            } else {
                ProcessApi::from_name(imported).map(ProcessBindingKind::Function)
            }
        }
        ProcessBindingKind::Promises => promises_api(imported).map(ProcessBindingKind::Function),
        ProcessBindingKind::Function(_) => None,
    }
}

fn pattern_selection_for_symbol<'a>(
    pattern: &BindingPattern<'a>,
    symbol: SymbolId,
    selection: PatternSelection<'a>,
) -> Option<PatternSelection<'a>> {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => {
            (identifier.symbol_id.get() == Some(symbol)).then_some(selection)
        }
        BindingPattern::AssignmentPattern(assignment) => {
            pattern_selection_for_symbol(&assignment.left, symbol, selection)
        }
        BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                let next = pattern_selection(selection, property_name(&property.key));
                if let Some(found) = pattern_selection_for_symbol(&property.value, symbol, next) {
                    return Some(found);
                }
            }
            None
        }
        BindingPattern::ArrayPattern(_) => None,
    }
}

fn pattern_selection<'a>(
    selection: PatternSelection<'a>,
    property: Option<&'a str>,
) -> PatternSelection<'a> {
    let Some(property) = property else {
        return PatternSelection::Unknown;
    };
    match selection {
        PatternSelection::Whole => PatternSelection::Property(property),
        PatternSelection::Property("promises") => PatternSelection::PromisesProperty(property),
        PatternSelection::Property(_) | PatternSelection::PromisesProperty(_) => {
            PatternSelection::Unknown
        }
        PatternSelection::Unknown => PatternSelection::Unknown,
    }
}

fn project_selection(
    source: ProcessBindingKind,
    selection: PatternSelection<'_>,
) -> Option<ProcessBindingKind> {
    match selection {
        PatternSelection::Whole => Some(source),
        PatternSelection::Property(property) => property_kind(source, property),
        PatternSelection::PromisesProperty(property) => {
            property_kind(source, "promises").and_then(|kind| property_kind(kind, property))
        }
        PatternSelection::Unknown => None,
    }
}

fn property_kind(source: ProcessBindingKind, property: &str) -> Option<ProcessBindingKind> {
    member_kind(source, MemberPath::Direct(property))
}

fn member_kind(source: ProcessBindingKind, path: MemberPath<'_>) -> Option<ProcessBindingKind> {
    let (promises_path, property) = match path {
        MemberPath::Direct(property) => (false, property),
        MemberPath::Promises(property) => (true, property),
    };
    if promises_path {
        return match source {
            ProcessBindingKind::ChildProcess => {
                promises_api(property).map(ProcessBindingKind::Function)
            }
            ProcessBindingKind::Promises | ProcessBindingKind::Function(_) => None,
        };
    }
    if property == "promises" {
        return matches!(source, ProcessBindingKind::ChildProcess)
            .then_some(ProcessBindingKind::Promises);
    }
    match source {
        ProcessBindingKind::ChildProcess => {
            ProcessApi::from_name(property).map(ProcessBindingKind::Function)
        }
        ProcessBindingKind::Promises => promises_api(property).map(ProcessBindingKind::Function),
        ProcessBindingKind::Function(_) => None,
    }
}

fn promises_api(name: &str) -> Option<ProcessApi> {
    match ProcessApi::from_name(name) {
        Some(api @ (ProcessApi::Exec | ProcessApi::ExecFile | ProcessApi::Spawn)) => Some(api),
        Some(ProcessApi::ExecSync | ProcessApi::ExecFileSync | ProcessApi::SpawnSync) | None => {
            None
        }
    }
}

fn module_kind(module: &str) -> Option<ProcessBindingKind> {
    match module {
        "child_process" | "node:child_process" => Some(ProcessBindingKind::ChildProcess),
        "child_process/promises" | "node:child_process/promises" => {
            Some(ProcessBindingKind::Promises)
        }
        _ => None,
    }
}

fn binding_source<'a>(expression: &Expression<'a>) -> BindingSource<'a> {
    let expression = unparenthesized(expression);
    if let Some(require) = require_root(expression) {
        return BindingSource::Root(require);
    }
    if let Expression::Identifier(identifier) = expression {
        return BindingSource::Root(RootSource::Identifier {
            reference_id: identifier.reference_id.get(),
            at: identifier.span.start,
        });
    }
    let Some(member) = expression.as_member_expression() else {
        return BindingSource::Unknown;
    };
    let Some(property) = member_property_name(member) else {
        return BindingSource::Unknown;
    };
    let object = unparenthesized(member_object(member));
    if property == "promises" {
        return root_source(object).map_or(BindingSource::Unknown, |root| BindingSource::Member {
            root,
            path: MemberPath::Direct(property),
        });
    }
    if ProcessApi::from_name(property).is_none() {
        return BindingSource::Unknown;
    }
    if let Some(root) = root_source(object) {
        return BindingSource::Member {
            root,
            path: MemberPath::Direct(property),
        };
    }
    let Some(promises_member) = object.as_member_expression() else {
        return BindingSource::Unknown;
    };
    if member_property_name(promises_member) != Some("promises") {
        return BindingSource::Unknown;
    }
    let Some(root) = root_source(unparenthesized(member_object(promises_member))) else {
        return BindingSource::Unknown;
    };
    BindingSource::Member {
        root,
        path: MemberPath::Promises(property),
    }
}

fn root_source<'a>(expression: &Expression<'a>) -> Option<RootSource<'a>> {
    let expression = unparenthesized(expression);
    if let Some(require) = require_root(expression) {
        return Some(require);
    }
    match expression {
        Expression::Identifier(identifier) => Some(RootSource::Identifier {
            reference_id: identifier.reference_id.get(),
            at: identifier.span.start,
        }),
        _ => None,
    }
}

fn require_root<'a>(expression: &Expression<'a>) -> Option<RootSource<'a>> {
    let Expression::CallExpression(call) = unparenthesized(expression) else {
        return None;
    };
    let Expression::Identifier(identifier) = unparenthesized(&call.callee) else {
        return None;
    };
    if identifier.name != "require" || call.arguments.len() != 1 {
        return None;
    }
    let Expression::StringLiteral(module) = unparenthesized(call.arguments[0].as_expression()?)
    else {
        return None;
    };
    Some(RootSource::Require {
        module: module.value.as_str(),
        require_reference: identifier.reference_id.get(),
    })
}

fn member_property_name<'a>(member: &MemberExpression<'a>) -> Option<&'a str> {
    match member {
        MemberExpression::StaticMemberExpression(member) => Some(member.property.name.as_str()),
        MemberExpression::ComputedMemberExpression(member) => {
            match unparenthesized(&member.expression) {
                Expression::StringLiteral(literal) => Some(literal.value.as_str()),
                _ => None,
            }
        }
        MemberExpression::PrivateFieldExpression(_) => None,
    }
}

fn module_export_name<'a>(name: &ModuleExportName<'a>) -> &'a str {
    match name {
        ModuleExportName::IdentifierName(identifier) => identifier.name.as_str(),
        ModuleExportName::IdentifierReference(identifier) => identifier.name.as_str(),
        ModuleExportName::StringLiteral(literal) => literal.value.as_str(),
    }
}

fn property_name<'a>(key: &PropertyKey<'a>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(identifier.name.as_str()),
        PropertyKey::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

fn source_position(source: &BindingSource<'_>) -> u32 {
    let root = match source {
        BindingSource::Root(root) | BindingSource::Member { root, .. } => *root,
        BindingSource::Unknown => return 0,
    };
    match root {
        RootSource::Identifier { at, .. } => at,
        RootSource::Require { .. } => 0,
    }
}

impl SecurityHotspotCollector<'_, '_> {
    /// `S4721` and `S4036`: shell-interpreter sinks and PATH lookups.
    pub(crate) fn check_shell_exec(&mut self, call: &CallExpression<'_>) {
        if self.process_bindings.is_shell_exec(call) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4721",
                "Prefer 'spawn' over 'exec': 'exec' runs a shell interpreter.",
                call.span(),
            );
        }
        if self.process_bindings.is_path_lookup(call)
            && let Some(executable) = first_string_argument(call)
            && !executable.contains('/')
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4036",
                "Make sure the \"PATH\" used to find this command includes only what you intend.",
                call.arguments
                    .first()
                    .and_then(argument_expression)
                    .map_or(call.span(), GetSpan::span),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{count_key, ts_keys};

    #[test]
    fn s4721_requires_node_child_process_ownership() {
        let clean = ts_keys(
            "declare const text: string;\n\
             const value = RegExp(/x/).exec(text);\n\
             console.log(value);\n\
             const custom = { exec: () => undefined };\n\
             custom.exec(\"ls\");\n\
             exec(\"ls\");\n",
        );
        assert_eq!(count_key(&clean, "typescript:S4721"), 0);
        assert_eq!(count_key(&clean, "typescript:S4036"), 0);
    }

    #[test]
    fn s4721_resolves_aliases_namespaces_and_shadowing() {
        let findings = ts_keys(
            "import { exec as run } from \"node:child_process\";\n\
             const child = require(\"child_process\");\n\
             const { exec: from_destructure } = child;\n\
             run(\"ls\");\n\
             from_destructure(\"ls\");\n\
             child.exec(\"ls\");\n\
             child.promises.exec(\"ls\");\n\
             function ignored(run: (command: string) => void) {\n\
                 run(\"ls\");\n\
             }\n",
        );
        assert_eq!(count_key(&findings, "typescript:S4721"), 4);
        assert_eq!(count_key(&findings, "typescript:S4036"), 4);
    }
}
