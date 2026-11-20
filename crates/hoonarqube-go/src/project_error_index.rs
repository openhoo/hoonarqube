//! Immutable builtin-error return positions from a complete selected Go snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use hoonarqube_ir::FileClassification;
use sha2::{Digest as _, Sha256};
use tree_sitter::Node;

use crate::{GoImports, ancestors, first_named, named_children, text, walk};

#[cfg(test)]
#[path = "s3776_project_tests.rs"]
mod tests;

/// Identity admitted by the outer, guarded project collector.
#[derive(Clone, Copy)]
pub struct ProjectSourceIdentity<'a> {
    pub normalized_path: &'a Path,
    pub physical_path: Option<&'a Path>,
    pub classification: FileClassification,
}

/// One explicitly selected input. Missing source is an explicit refusal input.
#[derive(Clone, Copy)]
pub struct ProjectSourceSnapshot<'a> {
    pub identity: ProjectSourceIdentity<'a>,
    pub source: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SourceRecord {
    path: PathBuf,
    physical: Option<PathBuf>,
    classification: u8,
    source_digest: Option<String>,
    admitted: bool,
}

impl SourceRecord {
    fn new(identity: ProjectSourceIdentity<'_>, source: Option<&str>) -> Self {
        let normalized = normalize_absolute(identity.normalized_path);
        let physical = identity.physical_path.and_then(normalize_absolute);
        Self {
            path: normalized
                .clone()
                .unwrap_or_else(|| identity.normalized_path.to_path_buf()),
            physical,
            classification: classification_code(identity.classification),
            source_digest: source.map(source_digest),
            admitted: normalized.is_some()
                && identity
                    .physical_path
                    .is_some_and(|p| normalize_absolute(p).is_some()),
        }
    }

    fn source_candidate(&self) -> bool {
        self.classification == classification_code(FileClassification::Source)
            && self.path.extension().is_some_and(|e| e == "go")
            && !self
                .path
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().ends_with(b"_test.go"))
    }
}

#[derive(Default)]
pub(crate) struct PackageErrorFacts {
    pub(crate) functions: BTreeMap<String, Vec<bool>>,
    pub(crate) variables: BTreeMap<String, Vec<bool>>,
}

struct FileFacts {
    package: String,
    names: BTreeMap<String, usize>,
    functions: BTreeMap<String, Vec<bool>>,
    variables: BTreeSet<String>,
    writes: BTreeSet<String>,
    refused: bool,
}

/// Conservative project facts, bound to the exact selected identities and bytes.
///
/// Construction performs no filesystem, environment, compiler, or import loading.
/// Unavailable or ambiguous members disable their affected Source directory.
/// The known signature of a function variable does not prove its runtime target.
pub struct ProjectErrorIndex {
    digest: String,
    targets: BTreeMap<PathBuf, Option<SourceRecord>>,
    groups: BTreeMap<PathBuf, PackageErrorFacts>,
}

impl ProjectErrorIndex {
    #[must_use]
    pub fn build(selected: &[ProjectSourceSnapshot<'_>]) -> Self {
        // Exact duplicates are idempotent. Conflicts remain separate records.
        let records: BTreeMap<_, _> = selected
            .iter()
            .map(|snapshot| {
                (
                    SourceRecord::new(snapshot.identity, snapshot.source),
                    snapshot.source,
                )
            })
            .collect();
        let targets = collect_targets(records.keys());
        let mut membership = IndexMembership::default();
        for (record, source) in &records {
            membership.add(record, *source);
        }
        membership.refuse_aliases();
        membership.refuse_conflicts(&targets, &records.keys());
        Self {
            digest: records_digest(records.keys()),
            targets,
            groups: membership.package_groups(),
        }
    }

    /// Versioned SHA-256 of every selected, refused, and unavailable input.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) fn facts_for(
        &self,
        target: ProjectSourceIdentity<'_>,
        source: &str,
    ) -> Option<&PackageErrorFacts> {
        let current = SourceRecord::new(target, Some(source));
        if !current.admitted || !current.source_candidate() {
            return None;
        }
        let registered = self.targets.get(&current.path)?.as_ref()?;
        if registered != &current {
            return None;
        }
        self.groups.get(current.physical.as_deref()?.parent()?)
    }
}

#[derive(Default)]
struct IndexMembership<'a> {
    refused_normal: BTreeSet<PathBuf>,
    refused_physical: BTreeSet<PathBuf>,
    normal_parents: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
    physical_files: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
    members: BTreeMap<PathBuf, Vec<(&'a SourceRecord, Option<FileFacts>)>>,
}

impl<'a> IndexMembership<'a> {
    fn add(&mut self, record: &'a SourceRecord, source: Option<&str>) {
        if let Some(physical) = &record.physical {
            self.physical_files
                .entry(physical.clone())
                .or_default()
                .insert(record.path.clone());
        }
        if !record.source_candidate() {
            return;
        }
        let normal_parent = record.path.parent().unwrap_or(&record.path).to_path_buf();
        let Some(physical_parent) = record.physical.as_deref().and_then(Path::parent) else {
            self.refused_normal.insert(normal_parent);
            return;
        };
        self.normal_parents
            .entry(normal_parent.clone())
            .or_default()
            .insert(physical_parent.to_path_buf());
        if !record.admitted || source.is_none() {
            self.refused_normal.insert(normal_parent);
        }
        self.members
            .entry(physical_parent.to_path_buf())
            .or_default()
            .push((record, source.and_then(collect_file_facts)));
    }

    fn refuse_aliases(&mut self) {
        for (normal, physical) in &self.normal_parents {
            if physical.len() != 1 {
                self.refused_normal.insert(normal.clone());
            }
        }
        for (physical, paths) in &self.physical_files {
            if paths.len() != 1
                && let Some(parent) = physical.parent()
            {
                self.refused_physical.insert(parent.to_path_buf());
            }
        }
    }

    fn refuse_conflicts(
        &mut self,
        targets: &BTreeMap<PathBuf, Option<SourceRecord>>,
        records: &(impl Iterator<Item = &'a SourceRecord> + Clone),
    ) {
        for (path, _) in targets.iter().filter(|(_, target)| target.is_none()) {
            if let Some(parent) = path.parent() {
                self.refused_normal.insert(parent.to_path_buf());
            }
            for record in records.clone().filter(|record| record.path == *path) {
                if let Some(parent) = record.physical.as_deref().and_then(Path::parent) {
                    self.refused_physical.insert(parent.to_path_buf());
                }
            }
        }
    }

    fn package_groups(self) -> BTreeMap<PathBuf, PackageErrorFacts> {
        self.members
            .into_iter()
            .filter_map(|(parent, files)| {
                if self.refused_physical.contains(&parent)
                    || files.iter().any(|(record, facts)| {
                        record
                            .path
                            .parent()
                            .is_some_and(|p| self.refused_normal.contains(p))
                            || facts.is_none()
                    })
                {
                    return None;
                }
                package_facts(&files).map(|facts| (parent, facts))
            })
            .collect()
    }
}

fn collect_targets<'a>(
    records: impl Iterator<Item = &'a SourceRecord>,
) -> BTreeMap<PathBuf, Option<SourceRecord>> {
    let mut targets = BTreeMap::new();
    for record in records {
        targets
            .entry(record.path.clone())
            .and_modify(|target| *target = None)
            .or_insert_with(|| Some(record.clone()));
    }
    targets
}

fn normalize_absolute(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Some(normalized)
}

fn classification_code(classification: FileClassification) -> u8 {
    match classification {
        FileClassification::Source => 0,
        FileClassification::Test => 1,
        FileClassification::Excluded => 2,
        FileClassification::Generated => 3,
        FileClassification::Vendor => 4,
    }
}

fn source_digest(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn records_digest<'a>(records: impl Iterator<Item = &'a SourceRecord>) -> String {
    let mut hasher = Sha256::new();
    hash_field(
        &mut hasher,
        b"hoonarqube-go-s3776-selected-project-context-v1",
    );
    for record in records {
        hash_field(&mut hasher, record.path.as_os_str().as_encoded_bytes());
        hash_field(&mut hasher, &[u8::from(record.physical.is_some())]);
        hash_field(
            &mut hasher,
            record
                .physical
                .as_deref()
                .map_or(b"", |p| p.as_os_str().as_encoded_bytes()),
        );
        hash_field(
            &mut hasher,
            &[record.classification, u8::from(record.admitted)],
        );
        hash_field(&mut hasher, &[u8::from(record.source_digest.is_some())]);
        hash_field(
            &mut hasher,
            record.source_digest.as_deref().unwrap_or("").as_bytes(),
        );
    }
    format!("{:x}", hasher.finalize())
}

fn collect_file_facts(original: &str) -> Option<FileFacts> {
    let (source, tree) = crate::parse_go_source(original)?;
    let source = source.as_ref();
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let package = named_children(root)
        .into_iter()
        .find(|node| node.kind() == "package_clause")
        .and_then(first_named)?;
    let imports = GoImports::collect(root, source);
    let mut facts = FileFacts {
        package: text(package, source).to_owned(),
        names: BTreeMap::new(),
        functions: BTreeMap::new(),
        variables: BTreeSet::new(),
        writes: BTreeSet::new(),
        refused: has_build_directive(source)
            || imports.non_blank_import("C")
            || !imports.dot_imports.is_empty(),
    };
    let mut variables = Vec::new();
    let mut import_names = ImportNames::default();
    walk(root, &mut |node| {
        collect_writes(node, source, &mut facts.writes);
        if ancestors(node).any(crate::is_function) {
            return;
        }
        match node.kind() {
            "function_declaration" => collect_function(node, source, &mut facts),
            "var_spec" | "const_spec" | "type_spec" | "type_alias" => {
                collect_package_names(node, source, &mut facts.names);
                if node.kind() == "var_spec" {
                    variables.push(node);
                }
            }
            "import_spec" => facts.refused |= import_names.record(node, source),
            _ => {}
        }
    });
    for node in variables {
        if let Some(name) = regexp_variable(node, source, &imports, &facts.names) {
            facts.variables.insert(name);
        }
    }
    Some(facts)
}

fn collect_function(node: Node<'_>, source: &str, facts: &mut FileFacts) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let name = text(name, source);
    if name == "init" || name == "_" {
        return;
    }
    *facts.names.entry(name.to_owned()).or_default() += 1;
    if node.child_by_field_name("type_parameters").is_none() {
        facts
            .functions
            .insert(name.to_owned(), return_positions(node, source));
    }
}

fn collect_package_names(node: Node<'_>, source: &str, names: &mut BTreeMap<String, usize>) {
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        let name = text(name, source);
        if name != "_" {
            *names.entry(name.to_owned()).or_default() += 1;
        }
    }
}

#[derive(Default)]
struct ImportNames {
    aliases: BTreeSet<String>,
    paths: BTreeSet<String>,
}

impl ImportNames {
    fn record(&mut self, node: Node<'_>, source: &str) -> bool {
        let Some(path) = node.child_by_field_name("path") else {
            return false;
        };
        let path = text(path, source).trim_matches(['"', '`']);
        let duplicate_path = !self.paths.insert(path.to_owned());
        let alias = node.child_by_field_name("name").map_or_else(
            || path.rsplit('/').next().unwrap_or(path),
            |n| text(n, source),
        );
        let duplicate_alias = alias != "_" && !self.aliases.insert(alias.to_owned());
        duplicate_path || duplicate_alias
    }
}

fn return_positions(function: Node<'_>, source: &str) -> Vec<bool> {
    let Some(result) = function.child_by_field_name("result") else {
        return Vec::new();
    };
    if result.kind() != "parameter_list" {
        return vec![text(result, source) == "error"];
    }
    let mut returns = Vec::new();
    for parameter in named_children(result)
        .into_iter()
        .filter(|p| p.kind() == "parameter_declaration")
    {
        let error = parameter
            .child_by_field_name("type")
            .is_some_and(|kind| text(kind, source) == "error");
        let mut cursor = parameter.walk();
        let count = parameter
            .children_by_field_name("name", &mut cursor)
            .count()
            .max(1);
        returns.extend(std::iter::repeat_n(error, count));
    }
    returns
}

fn regexp_variable(
    node: Node<'_>,
    source: &str,
    imports: &GoImports,
    names: &BTreeMap<String, usize>,
) -> Option<String> {
    if node.child_by_field_name("type").is_some() {
        return None;
    }
    let mut cursor = node.walk();
    let declarations: Vec<_> = node.children_by_field_name("name", &mut cursor).collect();
    if declarations.len() != 1 {
        return None;
    }
    let values = named_children(node.child_by_field_name("value")?);
    if values.len() != 1 || values[0].kind() != "selector_expression" {
        return None;
    }
    let value = values[0];
    let operand = value.child_by_field_name("operand")?;
    if operand.kind() != "identifier"
        || value.child_by_field_name("field").map(|n| text(n, source)) != Some("Compile")
    {
        return None;
    }
    let alias = text(operand, source);
    if imports.alias("regexp") != Some(alias) || names.contains_key(alias) {
        return None;
    }
    Some(text(declarations[0], source).to_owned())
}

fn collect_writes(node: Node<'_>, source: &str, writes: &mut BTreeSet<String>) {
    let left = match node.kind() {
        "assignment_statement" | "short_var_declaration" | "range_clause" | "receive_statement" => {
            node.child_by_field_name("left")
        }
        "inc_statement" | "dec_statement" => first_named(node),
        "unary_expression" if crate::operator_text(node, source) == "&" => {
            node.child_by_field_name("operand")
        }
        _ => None,
    };
    if let Some(left) = left {
        walk(left, &mut |name| {
            if name.kind() == "identifier" {
                writes.insert(text(name, source).to_owned());
            }
        });
    }
}

fn package_facts(files: &[(&SourceRecord, Option<FileFacts>)]) -> Option<PackageErrorFacts> {
    let mut package = None;
    let mut names = BTreeSet::new();
    let mut facts = PackageErrorFacts::default();
    let mut writes = BTreeSet::new();
    for (record, file) in files {
        let file = file.as_ref()?;
        if file.refused || platform_filename(&record.path) || file.package.ends_with("_test") {
            return None;
        }
        if package.is_some_and(|p| p != &file.package) {
            return None;
        }
        package = Some(&file.package);
        for (name, count) in &file.names {
            if *count != 1 || !names.insert(name) || name == "error" {
                return None;
            }
        }
        facts.functions.extend(file.functions.clone());
        facts.variables.extend(
            file.variables
                .iter()
                .map(|name| (name.clone(), vec![false, true])),
        );
        writes.extend(file.writes.iter().cloned());
    }
    facts.variables.retain(|name, _| !writes.contains(name));
    Some(facts)
}

fn has_build_directive(source: &str) -> bool {
    source.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("//go:build") || line.starts_with("// +build")
    })
}

fn platform_filename(path: &Path) -> bool {
    const PLATFORMS: &[&str] = &[
        "aix",
        "android",
        "darwin",
        "dragonfly",
        "freebsd",
        "hurd",
        "illumos",
        "ios",
        "js",
        "linux",
        "nacl",
        "netbsd",
        "openbsd",
        "plan9",
        "solaris",
        "wasip1",
        "windows",
        "zos",
        "386",
        "amd64",
        "amd64p32",
        "arm",
        "arm64",
        "arm64be",
        "armeb",
        "loong64",
        "mips",
        "mips64",
        "mips64le",
        "mips64p32",
        "mips64p32le",
        "mipsle",
        "ppc",
        "ppc64",
        "ppc64le",
        "riscv",
        "riscv64",
        "s390",
        "s390x",
        "sparc",
        "sparc64",
        "wasm",
    ];
    path.file_stem()
        .and_then(|name| name.to_str())
        .and_then(|name| name.rsplit_once('_'))
        .is_some_and(|(_, suffix)| PLATFORMS.contains(&suffix))
}
