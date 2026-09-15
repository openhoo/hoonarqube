//! Syntax-level cross-file type index for project-scope C# rules.
//!
//! The per-file analyzer resolves base types and type members through the
//! analyzed file only. Project-scope rules (`csharpsquid:S4019`) and the
//! cross-partial GitHub Code Quality shadow checks need the same resolution
//! across every accepted source file of a scan, so the CLI builds one
//! immutable index per run and threads it through the analyzer options. The
//! index is purely syntactic: files whose recovered tree contains parse
//! errors are skipped, mirroring the analyzer's incomplete-file handling.
//!
//! Index construction and lookup are deliberately mechanical: a stable
//! content digest feeds cache keys, and the whole structure is immutable
//! once built.

use tree_sitter::Node;

use crate::cst::{
    base_simple_names, canonical_identifier, is_error_tainted, modifiers_of, node_text,
    parameter_signature_texts, range_of,
};
use crate::parse;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::support::{
    full_type_identity, has_explicit_interface_specifier, type_members,
};
use crate::rules::tier_c::support::local_type_declarations;
use crate::semantic::{SourceSnapshot, digest_bytes, is_razor_path};
use hoonarqube_ir::Range;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

/// One indexed parameter: signature identity plus message spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexedParameter {
    /// Ordered `ref`/`out`/`in`/`scoped`/`readonly` prefixes; empty when the
    /// parameter is passed by plain value.
    pub(crate) ref_kind: String,
    /// Whitespace-stripped type text with trailing nullability annotations
    /// removed; the comparison identity of the parameter type.
    pub(crate) type_key: String,
    /// Written parameter type text, used verbatim in messages.
    pub(crate) display: String,
}

/// One same-name method declaration of an indexed type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexedMethod {
    pub(crate) parameters: Vec<IndexedParameter>,
}

/// One member (field, property, event) of an indexed type: the shadow
/// checks need its staticness plus a cross-file anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexedMember {
    pub(crate) name: String,
    pub(crate) is_static: bool,
    pub(crate) path: PathBuf,
    pub(crate) range: Range,
}

/// One indexed type declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IndexedType {
    /// Fully qualified syntactic identity (`namespace.outer.inner`), shared
    /// by every partial declaration of the type.
    pub(crate) identity: String,
    /// Simple names of every base in the type's base list.
    pub(crate) bases: Vec<String>,
    /// Declared methods grouped by simple name.
    pub(crate) methods: BTreeMap<String, Vec<IndexedMethod>>,
    /// Declared fields, properties, and events.
    pub(crate) members: Vec<IndexedMember>,
    /// Whether the declaration is an `interface`; interface member names
    /// drive the reference platform's interface-implementation exemptions.
    pub(crate) is_interface: bool,
    /// Whether the declaration carries the `abstract` modifier.
    pub(crate) is_abstract: bool,
}

/// Cross-file table of accepted C# type declarations, keyed by simple name.
pub struct ProjectTypeIndex {
    types: BTreeMap<String, Vec<IndexedType>>,
    digest: String,
}

impl ProjectTypeIndex {
    /// Indexes every parseable source snapshot. Unparseable or Razor sources
    /// are skipped, matching the analyzer's per-file acceptance contract.
    #[must_use]
    pub fn build(sources: &[SourceSnapshot]) -> Self {
        let mut types: BTreeMap<String, Vec<IndexedType>> = BTreeMap::new();
        for snapshot in sources {
            if is_razor_path(&snapshot.path) {
                continue;
            }
            index_source(&snapshot.path, &snapshot.source, &mut types);
        }
        Self {
            digest: index_digest(&types),
            types,
        }
    }

    /// Every same-name method declared by any indexed type of `type_name`.
    pub(crate) fn same_name_methods(
        &self,
        type_name: &str,
        method_name: &str,
    ) -> Vec<&IndexedMethod> {
        self.types
            .get(type_name)
            .into_iter()
            .flatten()
            .filter_map(|declaration| declaration.methods.get(method_name))
            .flatten()
            .collect()
    }

    /// Whether the indexed type `descendant` transitively inherits from the
    /// indexed type `ancestor` (both simple names).
    pub(crate) fn type_reaches(&self, descendant: &str, ancestor: &str) -> bool {
        if descendant == ancestor {
            return true;
        }
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::from([descendant]);
        while let Some(current) = queue.pop_front() {
            if !seen.insert(current) {
                continue;
            }
            for declaration in self.types.get(current).into_iter().flatten() {
                for base in &declaration.bases {
                    if base == ancestor {
                        return true;
                    }
                    queue.push_back(base);
                }
            }
        }
        false
    }

    /// Every indexed member (field, property, event) declared by any partial
    /// declaration sharing `identity`, across all accepted files.
    pub(crate) fn partial_members(&self, identity: &str) -> Vec<&IndexedMember> {
        self.types
            .values()
            .flatten()
            .filter(|declaration| declaration.identity == identity)
            .flat_map(|declaration| declaration.members.iter())
            .collect()
    }

    /// Every indexed declaration of the simple type name.
    pub(crate) fn type_declarations(&self, type_name: &str) -> impl Iterator<Item = &IndexedType> {
        self.types.get(type_name).into_iter().flatten()
    }

    /// Number of declarations sharing the fully qualified identity across all
    /// accepted files; partial-type rules compare this project-wide count.
    pub(crate) fn declaration_count(&self, identity: &str) -> usize {
        self.types
            .values()
            .flatten()
            .filter(|declaration| declaration.identity == identity)
            .count()
    }

    /// Stable content digest; cache keys and equality compares use this.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl PartialEq for ProjectTypeIndex {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl Eq for ProjectTypeIndex {}

impl std::fmt::Debug for ProjectTypeIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProjectTypeIndex")
            .field("type_count", &self.types.len())
            .field("digest", &self.digest)
            .finish()
    }
}

fn index_source(path: &Path, source: &str, types: &mut BTreeMap<String, Vec<IndexedType>>) {
    let tree = parse(source);
    let root = tree.root_node();
    if root.has_error() {
        return;
    }
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(name_node) = declaration.child_by_field_name("name") else {
            continue;
        };
        let Some(identity) = full_type_identity(declaration, source) else {
            continue;
        };
        let name = node_text(name_node, source).to_string();
        let modifiers = modifiers_of(declaration, source);
        let indexed = IndexedType {
            identity,
            bases: base_simple_names(declaration, source)
                .into_iter()
                .map(str::to_string)
                .collect(),
            methods: indexed_methods(declaration, source),
            members: indexed_members(declaration, path, source),
            is_interface: declaration.kind() == "interface_declaration",
            is_abstract: has_modifier(&modifiers, "abstract"),
        };
        types.entry(name).or_default().push(indexed);
    }
}

/// Declared fields, properties, and events of one type declaration with the
/// declaring file and range, so cross-file shadow findings can anchor the
/// shadowed member.
fn indexed_members(declaration: Node<'_>, path: &Path, source: &str) -> Vec<IndexedMember> {
    let mut members = Vec::new();
    for member in type_members(declaration) {
        if is_error_tainted(member) {
            continue;
        }
        match member.kind() {
            "field_declaration" | "event_field_declaration" => {
                let is_static = has_modifier(&modifiers_of(member, source), "static")
                    || has_modifier(&modifiers_of(member, source), "const");
                for declarator in direct_field_declarators(member) {
                    let Some(anchor) = declarator
                        .child_by_field_name("name")
                        .filter(|name| name.kind() == "identifier")
                    else {
                        continue;
                    };
                    members.push(IndexedMember {
                        name: canonical_identifier(node_text(anchor, source)).to_string(),
                        is_static,
                        path: path.to_path_buf(),
                        range: range_of(anchor, source),
                    });
                }
            }
            "property_declaration" | "event_declaration" => {
                let Some(name) = member
                    .child_by_field_name("name")
                    .filter(|name| name.kind() == "identifier")
                else {
                    continue;
                };
                members.push(IndexedMember {
                    name: canonical_identifier(node_text(name, source)).to_string(),
                    is_static: has_modifier(&modifiers_of(member, source), "static"),
                    path: path.to_path_buf(),
                    range: range_of(name, source),
                });
            }
            _ => {}
        }
    }
    members
}

fn direct_field_declarators(member: Node<'_>) -> Vec<Node<'_>> {
    let Some(declaration) = direct_named_children(member)
        .into_iter()
        .find(|child| child.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .filter(|child| child.kind() == "variable_declarator")
        .collect()
}

fn direct_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect()
}

fn indexed_methods(declaration: Node<'_>, source: &str) -> BTreeMap<String, Vec<IndexedMethod>> {
    let mut methods: BTreeMap<String, Vec<IndexedMethod>> = BTreeMap::new();
    for member in type_members(declaration) {
        if member.kind() != "method_declaration"
            || has_explicit_interface_specifier(member)
            || is_error_tainted(member)
        {
            continue;
        }
        let Some(name_node) = member.child_by_field_name("name") else {
            continue;
        };
        let parameters = parameter_signature_texts(member, source)
            .into_iter()
            .map(|(ref_kind, type_key, display)| IndexedParameter {
                ref_kind,
                type_key,
                display,
            })
            .collect();
        methods
            .entry(node_text(name_node, source).to_string())
            .or_default()
            .push(IndexedMethod { parameters });
    }
    methods
}
fn index_digest(types: &BTreeMap<String, Vec<IndexedType>>) -> String {
    let mut canonical = String::from("hoonarqube-csharp-project-type-index-v3\0");
    for (name, declarations) in types {
        for declaration in declarations {
            push_indexed_declaration(&mut canonical, name, declaration);
        }
    }
    digest_bytes(canonical.as_bytes())
}

/// Appends one indexed type declaration to the canonical digest form.
fn push_indexed_declaration(canonical: &mut String, name: &str, declaration: &IndexedType) {
    canonical.push_str(name);
    canonical.push('\u{1}');
    canonical.push_str(&declaration.identity);
    canonical.push('\u{1}');
    canonical.push_str(declaration.bases.join("\u{5}").as_str());
    canonical.push('\u{1}');
    canonical.push_str(if declaration.is_interface { "i" } else { "c" });
    canonical.push_str(if declaration.is_abstract { "a" } else { "s" });
    canonical.push('\u{1}');
    for (method_name, entries) in &declaration.methods {
        push_indexed_method(canonical, method_name, entries);
    }
    canonical.push('\u{1}');
    for member in &declaration.members {
        push_indexed_member(canonical, member);
    }
    canonical.push('\n');
}

/// Appends one overloaded method name with its parameter signatures.
fn push_indexed_method(canonical: &mut String, method_name: &str, entries: &[IndexedMethod]) {
    canonical.push_str(method_name);
    for entry in entries {
        for parameter in &entry.parameters {
            canonical.push('\u{2}');
            canonical.push_str(&parameter.ref_kind);
            canonical.push('\u{3}');
            canonical.push_str(&parameter.type_key);
        }
        canonical.push('\u{4}');
    }
}

/// Appends one member entry with its static flag, path, and range.
fn push_indexed_member(canonical: &mut String, member: &IndexedMember) {
    canonical.push_str(&member.name);
    canonical.push('\u{2}');
    canonical.push_str(if member.is_static { "s" } else { "i" });
    canonical.push('\u{3}');
    canonical.push_str(member.path.to_string_lossy().as_ref());
    canonical.push('\u{4}');
    canonical.push_str(member.range.start.line.to_string().as_str());
    canonical.push(':');
    canonical.push_str(member.range.start.column.to_string().as_str());
    canonical.push(':');
    canonical.push_str(member.range.end.line.to_string().as_str());
    canonical.push(':');
    canonical.push_str(member.range.end.column.to_string().as_str());
    canonical.push('\u{5}');
}
