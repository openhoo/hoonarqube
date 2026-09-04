//! Java parse context: exact source coordinates and conservative lexical facts.

use std::collections::BTreeMap;

use hoonarqube_ir::Range;
use tree_sitter::{Node, Parser, Tree};

use crate::support::{LineIndex, canonical_identifier, node_text, range_of, simple_name, walk_all};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeKind {
    CompilationUnit,
    Type,
    Method,
    Block,
    Loop,
    Lambda,
    Catch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolKind {
    Type,
    Method,
    Field,
    Local,
    Parameter,
    Label,
    Import,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeFact {
    Primitive(String),
    LocalType(String),
    JavaLang(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteSpan {
    start: usize,
    end: usize,
}

impl ByteSpan {
    fn contains(self, offset: usize) -> bool {
        self.start <= offset && offset <= self.end
    }
    fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }
}

#[derive(Debug, Clone)]
struct ScopeRecord {
    id: ScopeId,
    kind: ScopeKind,
    span: ByteSpan,
    range: Range,
    parent: Option<ScopeId>,
    symbols: BTreeMap<String, Vec<SymbolId>>,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub id: SymbolId,
    pub name: String,
    pub canonical_name: String,
    pub kind: SymbolKind,
    pub declared_at: Range,
    pub scope: ScopeId,
    pub type_fact: Option<TypeFact>,
    visibility: Option<Vec<ByteSpan>>,
    span: ByteSpan,
}

impl Symbol {
    pub(crate) fn byte_start(&self) -> usize {
        self.span.start
    }
}
#[derive(Debug)]
struct SymbolDeclaration<'tree> {
    kind: SymbolKind,
    name_node: Node<'tree>,
    type_node: Option<Node<'tree>>,
    owner: Node<'tree>,
    visibility: Option<Vec<ByteSpan>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFact {
    pub path: String,
    pub simple_name: String,
    pub is_static: bool,
    pub wildcard: bool,
    pub range: Range,
}

#[derive(Debug, Clone)]
pub struct ReferenceFact {
    pub name: String,
    pub range: Range,
    pub scope: ScopeId,
    pub symbol: Option<SymbolId>,
    pub is_declaration: bool,
    pub is_write: bool,
}

/// A complete, owned index of facts that can be proven from one Java CST.
/// External names remain unresolved unless they are explicit imports or local
/// declarations; no classpath assumptions are made.
#[derive(Debug, Clone)]
pub struct SemanticIndex {
    source_len: usize,
    scopes: Vec<ScopeRecord>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<ImportFact>,
    pub references: Vec<ReferenceFact>,
    package_name: Option<String>,
}

impl SemanticIndex {
    #[must_use]
    pub fn build(root: Node<'_>, source: &str, lines: &LineIndex) -> Self {
        let mut package_name = None;
        let mut imports = Vec::new();
        let mut seeds = vec![(
            ScopeKind::CompilationUnit,
            ByteSpan {
                start: 0,
                end: source.len(),
            },
        )];
        walk_all(root, &mut |node| {
            let span = ByteSpan {
                start: node.start_byte(),
                end: node.end_byte(),
            };
            match node.kind() {
                "package_declaration" => {
                    let value = declaration_tail(node_text(node, source), "package");
                    if !value.is_empty() {
                        package_name = Some(value);
                    }
                }
                "import_declaration" => {
                    if let Some(import) = parse_import(node, source, lines) {
                        imports.push(import);
                    }
                }
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration" => seeds.push((ScopeKind::Type, span)),
                "method_declaration"
                | "constructor_declaration"
                | "compact_constructor_declaration" => seeds.push((ScopeKind::Method, span)),
                "block" | "constructor_body" => seeds.push((ScopeKind::Block, span)),
                "for_statement" | "enhanced_for_statement" | "while_statement" | "do_statement" => {
                    seeds.push((ScopeKind::Loop, span));
                }
                "lambda_expression" => seeds.push((ScopeKind::Lambda, span)),
                "catch_clause" => seeds.push((ScopeKind::Catch, span)),
                _ => {}
            }
        });
        seeds.sort_by(|left, right| {
            left.1
                .start
                .cmp(&right.1.start)
                .then_with(|| right.1.end.cmp(&left.1.end))
        });
        seeds.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
        let mut scopes = Vec::with_capacity(seeds.len());
        for (index, (kind, span)) in seeds.into_iter().enumerate() {
            let parent = scopes
                .iter()
                .filter(|candidate: &&ScopeRecord| {
                    candidate.span.contains(span.start) && candidate.span.len() > span.len()
                })
                .min_by_key(|candidate| candidate.span.len())
                .map(|candidate| candidate.id);
            scopes.push(ScopeRecord {
                id: ScopeId(index),
                kind,
                span,
                range: lines.range(source, span.start, span.end),
                parent,
                symbols: BTreeMap::new(),
            });
        }
        let mut index = Self {
            source_len: source.len(),
            scopes,
            symbols: Vec::new(),
            imports,
            references: Vec::new(),
            package_name,
        };
        index.collect_declarations(root, source, lines);
        index.collect_references(root, source, lines);
        index
    }

    fn collect_declarations(&mut self, root: Node<'_>, source: &str, lines: &LineIndex) {
        walk_all(root, &mut |node| {
            self.collect_declaration(node, source, lines);
        });
    }

    fn collect_declaration(&mut self, node: Node<'_>, source: &str, lines: &LineIndex) {
        let kind = node.kind();
        if matches!(
            kind,
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ) {
            self.collect_type_declaration(node, source, lines);
            return;
        }
        if matches!(
            kind,
            "method_declaration" | "constructor_declaration" | "compact_constructor_declaration"
        ) {
            self.collect_method_declaration(node, source, lines);
            return;
        }
        if matches!(kind, "formal_parameter" | "spread_parameter") {
            self.collect_parameter_declaration(node, source, lines);
            return;
        }
        if matches!(
            kind,
            "local_variable_declaration" | "field_declaration" | "constant_declaration"
        ) {
            self.collect_variable_declaration(node, source, lines);
            return;
        }
        if matches!(kind, "enhanced_for_statement" | "catch_formal_parameter") {
            self.collect_local_declaration(node, source, lines);
            return;
        }
        if kind == "resource" && node.child_by_field_name("type").is_some() {
            self.collect_local_declaration(node, source, lines);
            return;
        }
        if kind == "enum_constant" {
            if let Some(name) = node.child_by_field_name("name") {
                self.add_symbol(SymbolKind::Field, name, None, node, source, lines);
            }
            return;
        }
        if kind == "lambda_expression" {
            self.collect_lambda_parameters(node, source, lines);
            return;
        }
        if matches!(
            kind,
            "type_pattern" | "record_pattern_component" | "instanceof_expression"
        ) {
            self.collect_pattern_declaration(node, source, lines);
            return;
        }
        if kind == "labeled_statement"
            && let Some(name) = node.named_child(0)
        {
            self.add_symbol(SymbolKind::Label, name, None, node, source, lines);
        }
    }

    fn collect_type_declaration(&mut self, node: Node<'_>, source: &str, lines: &LineIndex) {
        if let Some(name) = node.child_by_field_name("name") {
            self.add_symbol(SymbolKind::Type, name, None, node, source, lines);
        }
    }

    fn collect_method_declaration(&mut self, node: Node<'_>, source: &str, lines: &LineIndex) {
        if let Some(name) = node.child_by_field_name("name") {
            self.add_symbol(
                SymbolKind::Method,
                name,
                node.child_by_field_name("type"),
                node,
                source,
                lines,
            );
        }
    }

    fn collect_parameter_declaration(&mut self, node: Node<'_>, source: &str, lines: &LineIndex) {
        if let Some(name) = node
            .child_by_field_name("name")
            .or_else(|| last_name_descendant(node))
        {
            self.add_symbol(
                SymbolKind::Parameter,
                name,
                node.child_by_field_name("type"),
                node,
                source,
                lines,
            );
        }
    }

    fn collect_variable_declaration(&mut self, node: Node<'_>, source: &str, lines: &LineIndex) {
        let symbol_kind = if node.kind() == "local_variable_declaration" {
            SymbolKind::Local
        } else {
            SymbolKind::Field
        };
        for declarator in direct_declarators(node) {
            if let Some(name) = declarator
                .child_by_field_name("name")
                .or_else(|| first_name_descendant(declarator))
            {
                self.add_symbol(
                    symbol_kind.clone(),
                    name,
                    node.child_by_field_name("type"),
                    node,
                    source,
                    lines,
                );
            }
        }
    }

    fn collect_local_declaration(&mut self, node: Node<'_>, source: &str, lines: &LineIndex) {
        if let Some(name) = node
            .child_by_field_name("name")
            .or_else(|| last_name_descendant(node))
        {
            self.add_symbol(
                SymbolKind::Local,
                name,
                node.child_by_field_name("type"),
                node,
                source,
                lines,
            );
        }
    }

    fn collect_lambda_parameters(&mut self, node: Node<'_>, source: &str, lines: &LineIndex) {
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return;
        };
        if matches!(parameters.kind(), "identifier" | "_reserved_identifier") {
            self.add_symbol(SymbolKind::Parameter, parameters, None, node, source, lines);
        } else if parameters.kind() == "inferred_parameters" {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                self.add_symbol(SymbolKind::Parameter, parameter, None, node, source, lines);
            }
        }
    }

    fn collect_pattern_declaration(&mut self, node: Node<'_>, source: &str, lines: &LineIndex) {
        let (name, type_node) = if node.kind() == "instanceof_expression" {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                let pattern =
                    crate::support::collect_kinds(pattern, &["type_pattern", "record_pattern"])
                        .into_iter()
                        .next()
                        .unwrap_or(pattern);
                (
                    pattern
                        .child_by_field_name("name")
                        .or_else(|| pattern.named_child(1)),
                    pattern
                        .child_by_field_name("type")
                        .or_else(|| pattern.named_child(0)),
                )
            } else {
                (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("right"),
                )
            }
        } else {
            (node.named_child(1), node.named_child(0))
        };
        let Some(name) = name else {
            return;
        };
        if self.symbols.iter().any(|symbol| {
            symbol.span.start == name.start_byte() && symbol.span.end == name.end_byte()
        }) {
            return;
        }
        self.add_symbol_with_visibility(
            SymbolDeclaration {
                kind: SymbolKind::Local,
                name_node: name,
                type_node,
                owner: node,
                visibility: pattern_visibility(node, source),
            },
            source,
            lines,
        );
    }

    fn add_symbol(
        &mut self,
        kind: SymbolKind,
        name_node: Node<'_>,
        type_node: Option<Node<'_>>,
        owner: Node<'_>,
        source: &str,
        lines: &LineIndex,
    ) {
        self.add_symbol_with_visibility(
            SymbolDeclaration {
                kind,
                name_node,
                type_node,
                owner,
                visibility: None,
            },
            source,
            lines,
        );
    }

    fn add_symbol_with_visibility(
        &mut self,
        declaration: SymbolDeclaration<'_>,
        source: &str,
        lines: &LineIndex,
    ) {
        let SymbolDeclaration {
            kind,
            name_node,
            type_node,
            owner,
            visibility,
        } = declaration;
        let raw = node_text(name_node, source);
        let name = canonical_identifier(raw).to_owned();
        if name.is_empty() {
            return;
        }
        let scope = match kind {
            SymbolKind::Type | SymbolKind::Method => self
                .scope_for(owner.start_byte())
                .and_then(|id| self.scopes.get(id.0).and_then(|scope| scope.parent))
                .unwrap_or(ScopeId(0)),
            SymbolKind::Parameter => self
                .nearest_scope_of_kind(owner.start_byte(), &ScopeKind::Lambda)
                .or_else(|| self.nearest_scope_of_kind(owner.start_byte(), &ScopeKind::Method))
                .unwrap_or(ScopeId(0)),
            _ => self.scope_for(name_node.start_byte()).unwrap_or(ScopeId(0)),
        };
        let type_fact = type_node.and_then(|node| self.proven_type(node_text(node, source)));
        let id = SymbolId(self.symbols.len());
        let symbol = Symbol {
            id,
            name: raw.to_owned(),
            canonical_name: name.clone(),
            kind,
            declared_at: range_of(name_node, source, lines),
            scope,
            type_fact,
            visibility,
            span: ByteSpan {
                start: name_node.start_byte(),
                end: name_node.end_byte(),
            },
        };
        self.symbols.push(symbol);
        if let Some(scope) = self.scopes.get_mut(scope.0) {
            scope.symbols.entry(name).or_default().push(id);
        }
    }

    fn collect_references(&mut self, root: Node<'_>, source: &str, lines: &LineIndex) {
        walk_all(root, &mut |node| {
            if !matches!(
                node.kind(),
                "identifier" | "type_identifier" | "_reserved_identifier"
            ) {
                return;
            }
            let mut parent = node.parent();
            while let Some(ancestor) = parent {
                if matches!(
                    ancestor.kind(),
                    "package_declaration" | "import_declaration"
                ) {
                    return;
                }
                parent = ancestor.parent();
            }
            let text = canonical_identifier(node_text(node, source));
            if text.is_empty()
                || self.symbols.iter().any(|symbol| {
                    symbol.span.start == node.start_byte() && symbol.span.end == node.end_byte()
                })
            {
                return;
            }
            let scope = self.scope_for(node.start_byte()).unwrap_or(ScopeId(0));
            let is_write = is_write_reference(node);
            let symbol = self.resolve_in_scope(text, scope, node.start_byte());
            self.references.push(ReferenceFact {
                name: text.to_owned(),
                range: range_of(node, source, lines),
                scope,
                symbol,
                is_declaration: false,
                is_write,
            });
        });
        self.references.sort_by_key(|reference| {
            (
                reference.range.start,
                reference.range.end,
                reference.name.clone(),
            )
        });
    }

    fn proven_type(&self, text: &str) -> Option<TypeFact> {
        let text = text.trim();
        if matches!(
            text,
            "byte" | "short" | "int" | "long" | "char" | "float" | "double" | "boolean" | "void"
        ) {
            return Some(TypeFact::Primitive(text.to_owned()));
        }
        let simple = simple_name(text);
        if let Some(local) = self
            .symbols
            .iter()
            .find(|symbol| symbol.kind == SymbolKind::Type && symbol.canonical_name == simple)
        {
            return Some(TypeFact::LocalType(local.canonical_name.clone()));
        }
        if self.imports.iter().any(|import| {
            !import.wildcard
                && import.simple_name == simple
                && import.path != format!("java.lang.{simple}")
        }) {
            return None;
        }
        if matches!(
            simple,
            "String" | "StringBuffer" | "StringBuilder" | "Object"
        ) && (text == simple || text == format!("java.lang.{simple}"))
        {
            return Some(TypeFact::JavaLang(simple.to_owned()));
        }
        None
    }

    fn nearest_scope_of_kind(&self, offset: usize, kind: &ScopeKind) -> Option<ScopeId> {
        self.scopes
            .iter()
            .filter(|scope| &scope.kind == kind && scope.span.contains(offset))
            .min_by_key(|scope| scope.span.len())
            .map(|scope| scope.id)
    }

    fn scope_for(&self, offset: usize) -> Option<ScopeId> {
        self.scopes
            .iter()
            .filter(|scope| scope.span.contains(offset))
            .min_by_key(|scope| scope.span.len())
            .map(|scope| scope.id)
    }

    fn resolve_in_scope(&self, name: &str, mut scope: ScopeId, offset: usize) -> Option<SymbolId> {
        loop {
            let record = self.scopes.get(scope.0)?;
            if let Some(ids) = record.symbols.get(name)
                && let Some(id) = ids.iter().rev().copied().find(|id| {
                    let Some(symbol) = self.symbols.get(id.0) else {
                        return false;
                    };
                    symbol
                        .visibility
                        .as_ref()
                        .is_none_or(|ranges| ranges.iter().any(|range| range.contains(offset)))
                        && (matches!(
                            symbol.kind,
                            SymbolKind::Type
                                | SymbolKind::Method
                                | SymbolKind::Field
                                | SymbolKind::Label
                                | SymbolKind::Import
                        ) || symbol.span.start <= offset)
                })
            {
                return Some(id);
            }
            scope = record.parent?;
        }
    }

    /// Resolves a lexical symbol using nearest-scope shadowing.
    #[must_use]
    pub fn resolve_simple_name(&self, name: &str, scope: ScopeId) -> Option<&Symbol> {
        let canonical = canonical_identifier(name);
        let id = self.resolve_in_scope(canonical, scope, self.source_len)?;
        self.symbols.get(id.0)
    }

    pub(crate) fn empty() -> Self {
        Self {
            source_len: 0,
            scopes: vec![ScopeRecord {
                id: ScopeId(0),
                kind: ScopeKind::CompilationUnit,
                span: ByteSpan { start: 0, end: 0 },

                range: Range::file_level(),
                parent: None,
                symbols: BTreeMap::new(),
            }],
            symbols: Vec::new(),
            imports: Vec::new(),
            references: Vec::new(),
            package_name: None,
        }
    }

    /// Resolves only an explicit import or a locally declared type. Wildcard
    /// imports intentionally remain unresolved without classpath evidence.
    #[must_use]
    pub fn resolve_imported_name(&self, name: &str) -> Option<String> {
        self.imports
            .iter()
            .find(|import| !import.wildcard && import.simple_name == canonical_identifier(name))
            .map(|import| import.path.clone())
    }

    #[must_use]
    pub fn scope_range(&self, scope: ScopeId) -> Option<Range> {
        self.scopes.get(scope.0).map(|scope| scope.range.clone())
    }

    #[must_use]
    pub fn scope_kind(&self, scope: ScopeId) -> Option<ScopeKind> {
        self.scopes.get(scope.0).map(|scope| scope.kind.clone())
    }

    #[must_use]
    pub fn package_name(&self) -> Option<&str> {
        self.package_name.as_deref()
    }
}

fn pattern_visibility(node: Node<'_>, source: &str) -> Option<Vec<ByteSpan>> {
    let Some((control, condition)) = enclosing_condition(node) else {
        return switch_visibility(node);
    };
    let inverted = pattern_is_inverted(node, condition, source)?;
    let mut ranges = Vec::new();
    append_condition_visibility(node, condition, source, inverted, &mut ranges)?;
    append_control_visibility(control, inverted, &mut ranges);
    Some(ranges)
}

fn enclosing_condition(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut cursor = node;
    while let Some(parent) = cursor.parent() {
        if let Some(condition) = parent.child_by_field_name("condition")
            && condition.start_byte() <= node.start_byte()
            && condition.end_byte() >= node.end_byte()
        {
            return Some((parent, condition));
        }
        cursor = parent;
    }
    None
}

fn switch_visibility(node: Node<'_>) -> Option<Vec<ByteSpan>> {
    let mut current = node.parent()?;
    loop {
        if current.kind() == "switch_block_statement_group" {
            return Some(vec![ByteSpan {
                start: node.end_byte(),
                end: current.end_byte(),
            }]);
        }
        current = current.parent()?;
    }
}

fn pattern_is_inverted(node: Node<'_>, condition: Node<'_>, source: &str) -> Option<bool> {
    let mut inverted = false;
    let mut current = node;
    while current.id() != condition.id() {
        let parent = current.parent()?;
        if is_negation(parent, source) {
            inverted = !inverted;
        }
        current = parent;
    }
    Some(inverted)
}

fn is_negation(node: Node<'_>, source: &str) -> bool {
    node.kind() == "unary_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(operator, source) == "!")
}

fn append_condition_visibility(
    node: Node<'_>,
    condition: Node<'_>,
    source: &str,
    inverted: bool,
    ranges: &mut Vec<ByteSpan>,
) -> Option<()> {
    if !inverted && condition.end_byte() > node.end_byte() {
        let mut current = node;
        let mut allowed = true;
        while current.id() != condition.id() {
            let parent = current.parent()?;
            if is_or_expression(parent, source) {
                allowed = false;
                break;
            }
            current = parent;
        }
        if allowed {
            ranges.push(ByteSpan {
                start: node.end_byte(),
                end: condition.end_byte(),
            });
        }
    }
    Some(())
}

fn is_or_expression(node: Node<'_>, source: &str) -> bool {
    node.kind() == "binary_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(operator, source) == "||")
}

fn append_control_visibility(control: Node<'_>, inverted: bool, ranges: &mut Vec<ByteSpan>) {
    let branch = match control.kind() {
        "if_statement" => {
            if inverted {
                control.child_by_field_name("alternative")
            } else {
                control.child_by_field_name("consequence")
            }
        }
        "while_statement" | "for_statement" | "enhanced_for_statement" | "do_statement"
            if !inverted =>
        {
            None
        }
        _ => None,
    };
    if let Some(branch) = branch {
        ranges.push(ByteSpan {
            start: branch.start_byte(),
            end: branch.end_byte(),
        });
    }
}

fn declaration_tail(text: &str, keyword: &str) -> String {
    text.trim()
        .trim_start_matches(keyword)
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_owned()
}

fn parse_import(node: Node<'_>, source: &str, lines: &LineIndex) -> Option<ImportFact> {
    let components: Vec<_> = crate::support::collect_kinds(
        node,
        &["identifier", "type_identifier", "_reserved_identifier"],
    )
    .into_iter()
    .map(|part| canonical_identifier(node_text(part, source)).to_owned())
    .filter(|part| !part.is_empty())
    .collect();
    if components.is_empty() {
        return None;
    }
    let wildcard = crate::support::collect_kinds(node, &["asterisk"])
        .into_iter()
        .next()
        .is_some();
    let path = components.join(".");
    let simple_name = if wildcard {
        "*".to_owned()
    } else {
        components.last()?.clone()
    };
    let mut cursor = node.walk();
    let is_static = node
        .children(&mut cursor)
        .any(|child| child.kind() == "static");
    Some(ImportFact {
        path,
        simple_name,
        is_static,
        wildcard,
        range: range_of(node, source, lines),
    })
}

fn direct_declarators(node: Node<'_>) -> Vec<Node<'_>> {
    let mut result = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            result.push(child);
        }
    }
    result
}

fn first_name_descendant(node: Node<'_>) -> Option<Node<'_>> {
    let mut result = None;
    walk_all(node, &mut |candidate| {
        if result.is_none()
            && matches!(
                candidate.kind(),
                "identifier" | "type_identifier" | "_reserved_identifier" | "underscore_pattern"
            )
        {
            result = Some(candidate);
        }
    });
    result
}

fn last_name_descendant(node: Node<'_>) -> Option<Node<'_>> {
    let mut result = None;
    walk_all(node, &mut |candidate| {
        if matches!(
            candidate.kind(),
            "identifier" | "type_identifier" | "_reserved_identifier" | "underscore_pattern"
        ) {
            result = Some(candidate);
        }
    });
    result
}
fn is_write_reference(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "assignment_expression" {
            return parent.child_by_field_name("left").is_some_and(|left| {
                left.start_byte() <= node.start_byte() && left.end_byte() >= node.end_byte()
            });
        }
        if parent.kind() == "update_expression" {
            return true;
        }
        if matches!(
            parent.kind(),
            "expression_statement" | "block" | "method_invocation" | "argument_list"
        ) {
            break;
        }
        current = parent;
    }
    false
}

/// Parses Java with tree-sitter recovery enabled.
#[must_use]
pub fn parse(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

#[cfg(test)]
mod tests {
    use super::{ScopeId, ScopeKind, SemanticIndex, parse};
    use crate::support::LineIndex;

    #[test]
    fn scopes_resolve_nearest_shadowing_local() {
        let source =
            "class A { int value; void f(int value) { { int value = 1; value++; } value++; } }";
        let tree = parse(source).expect("valid Java fixture");
        let lines = LineIndex::new(source);
        let index = SemanticIndex::build(tree.root_node(), source, &lines);
        assert!(
            index
                .scopes
                .iter()
                .any(|scope| scope.kind == ScopeKind::Method)
        );
        let refs: Vec<_> = index
            .references
            .iter()
            .filter(|reference| reference.name == "value" && reference.is_write)
            .collect();
        assert_eq!(refs.len(), 2);
        assert_ne!(refs[0].symbol, refs[1].symbol);
    }

    #[test]
    fn imports_are_exact_and_wildcards_are_not_guessed() {
        let source = "package p; import java.util.List; import java.util.*; class A {}";
        let tree = parse(source).expect("valid Java fixture");
        let index = SemanticIndex::build(tree.root_node(), source, &LineIndex::new(source));
        assert_eq!(
            index.resolve_imported_name("List").as_deref(),
            Some("java.util.List")
        );
        assert_eq!(index.resolve_imported_name("Map"), None);
        assert_eq!(index.package_name(), Some("p"));
        assert!(index.resolve_simple_name("p", ScopeId(0)).is_none());
        assert!(
            index
                .resolve_simple_name("anything", ScopeId(usize::MAX))
                .is_none()
        );
    }
}
