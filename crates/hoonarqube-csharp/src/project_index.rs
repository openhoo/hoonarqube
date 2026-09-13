//! Syntax-level cross-file type index for project-scope C# rules.
//!
//! The per-file analyzer resolves base types through the analyzed file only.
//! Project-scope rules (currently `csharpsquid:S4019`) need the same
//! resolution across every accepted source file of a scan, so the CLI builds
//! one immutable index per run and threads it through the analyzer options.
//! The index is purely syntactic: files whose recovered tree contains parse
//! errors are skipped, mirroring the analyzer's incomplete-file handling.
//!
//! Index construction and lookup are deliberately mechanical: a stable
//! content digest feeds cache keys, and the whole structure is immutable
//! once built.

use tree_sitter::Node;

use crate::cst::{base_simple_names, is_error_tainted, node_text, parameter_signature_texts};
use crate::parse;
use crate::rules::naming::support::{has_explicit_interface_specifier, type_members};
use crate::rules::tier_c::support::local_type_declarations;
use crate::semantic::{SourceSnapshot, digest_bytes, is_razor_path};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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

/// One indexed type declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IndexedType {
    /// Simple names of every base in the type's base list.
    pub(crate) bases: Vec<String>,
    /// Declared methods grouped by simple name.
    pub(crate) methods: BTreeMap<String, Vec<IndexedMethod>>,
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
            index_source(&snapshot.source, &mut types);
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

fn index_source(source: &str, types: &mut BTreeMap<String, Vec<IndexedType>>) {
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
        let name = node_text(name_node, source).to_string();
        let indexed = IndexedType {
            bases: base_simple_names(declaration, source)
                .into_iter()
                .map(str::to_string)
                .collect(),
            methods: indexed_methods(declaration, source),
        };
        types.entry(name).or_default().push(indexed);
    }
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
    let mut canonical = String::from("hoonarqube-csharp-project-type-index-v1\0");
    for (name, declarations) in types {
        for declaration in declarations {
            canonical.push_str(name);
            canonical.push('\u{1}');
            canonical.push_str(declaration.bases.join("\u{5}").as_str());
            canonical.push('\u{1}');
            for (method_name, entries) in &declaration.methods {
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
            canonical.push('\n');
        }
    }
    digest_bytes(canonical.as_bytes())
}
