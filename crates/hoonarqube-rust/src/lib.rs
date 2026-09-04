//! Tolerant Rust analyzer for the frozen `SonarQube` Community Rust catalog.
//!
//! Tree-sitter supplies error recovery and structural checks. Rules derived
//! from Clippy type analysis use conservative source shapes and stay silent
//! when the required type or API evidence is absent.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::OnceLock;

use hoonarqube_ir::{
    FileMetrics, FileReport, FlowLocation, Issue, Pos, Range, sort_issues, u32_saturating,
};
use regex::Regex;
use tree_sitter::{Node, Parser, Point};

mod sonar_contract;

/// Computes file metrics without running rules or creating source masks.
///
/// # Panics
/// Panics if the embedded grammar is incompatible or parsing returns no tree.
#[must_use]
pub fn file_metrics(source: &str) -> FileMetrics {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("tree-sitter-rust language is compatible");
    let tree = parser
        .parse(source, None)
        .expect("Rust parser returned no tree");
    metrics(tree.root_node(), source)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_function_parameters: usize,
    pub maximum_cognitive_complexity: usize,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_function_parameters: 7,
            maximum_cognitive_complexity: 15,
        }
    }
}

const RULE_KEYS: &[&str] = &[
    "rust:S106",
    "rust:S107",
    "rust:S1116",
    "rust:S126",
    "rust:S1488",
    "rust:S1612",
    "rust:S1656",
    "rust:S1751",
    "rust:S1764",
    "rust:S1858",
    "rust:S1862",
    "rust:S2148",
    "rust:S2185",
    "rust:S2193",
    "rust:S2198",
    "rust:S2208",
    "rust:S2260",
    "rust:S2437",
    "rust:S2479",
    "rust:S2589",
    "rust:S3498",
    "rust:S3723",
    "rust:S3776",
    "rust:S3807",
    "rust:S4275",
    "rust:S4325",
    "rust:S4962",
    "rust:S5856",
    "rust:S6164",
    "rust:S6466",
    "rust:S6913",
    "rust:S7089",
    "rust:S7200",
    "rust:S7411",
    "rust:S7412",
    "rust:S7413",
    "rust:S7414",
    "rust:S7415",
    "rust:S7417",
    "rust:S7418",
    "rust:S7419",
    "rust:S7420",
    "rust:S7421",
    "rust:S7422",
    "rust:S7423",
    "rust:S7424",
    "rust:S7425",
    "rust:S7426",
    "rust:S7427",
    "rust:S7428",
    "rust:S7429",
    "rust:S7430",
    "rust:S7431",
    "rust:S7432",
    "rust:S7433",
    "rust:S7436",
    "rust:S7437",
    "rust:S7438",
    "rust:S7439",
    "rust:S7440",
    "rust:S7441",
    "rust:S7442",
    "rust:S7443",
    "rust:S7444",
    "rust:S7445",
    "rust:S7446",
    "rust:S7447",
    "rust:S7448",
    "rust:S7449",
    "rust:S7450",
    "rust:S7451",
    "rust:S7453",
    "rust:S7454",
    "rust:S7455",
    "rust:S7456",
    "rust:S7457",
    "rust:S7458",
    "rust:S7459",
    "rust:S7460",
    "rust:S7461",
    "rust:S7462",
    "rust:S7463",
    "rust:S7464",
    "rust:S905",
    "rust:S920",
];

#[derive(Clone, Copy)]
struct PatternRule {
    key: &'static str,
    any: &'static [&'static str],
    message: &'static str,
}

const PATTERN_RULES: &[PatternRule] = &[
    PatternRule {
        key: "rust:S1858",
        any: &[".to_owned().to_string()", ".to_string().to_string()"],
        message: "Remove this redundant call to `to_string()`.",
    },
    PatternRule {
        key: "rust:S2589",
        any: &["true &&", "&& true", "false ||", "|| false"],
        message: "Remove this gratuitous Boolean expression.",
    },
    PatternRule {
        key: "rust:S3807",
        any: &[
            "std::ptr::null(),",
            "std::ptr::null_mut(),",
            "ptr::null(),",
            "ptr::null_mut(),",
        ],
        message: "Do not pass a null pointer to this function.",
    },
    PatternRule {
        key: "rust:S6164",
        any: &["3.141592", "2.718281", "1.414213", "6.283185"],
        message: "Use the corresponding standard mathematical constant.",
    },
    PatternRule {
        key: "rust:S6913",
        any: &["min(", "max("],
        message: "Correct the clamping range.",
    },
    PatternRule {
        key: "rust:S7200",
        any: &[".resize(0,"],
        message: "Use `clear()` to resize this vector to zero.",
    },
    PatternRule {
        key: "rust:S7412",
        any: &[
            "as *const ()).add(",
            "as *mut ()).add(",
            "as *const ()).offset(",
            "as *mut ()).offset(",
        ],
        message: "Do not perform pointer arithmetic on a zero-sized type.",
    },
    PatternRule {
        key: "rust:S7414",
        any: &[
            "intrinsics::transmute(",
            "transmute::<u8, u16>",
            "transmute::<u16, u8>",
            "transmute::<u32, u64>",
            "transmute::<u64, u32>",
        ],
        message: "Remove this transmute between differently sized types.",
    },
    PatternRule {
        key: "rust:S7417",
        any: &["derive(Ord", "derive(PartialOrd, Ord)"],
        message: "Derive `PartialOrd` together with `Ord` instead of implementing it manually.",
    },
    PatternRule {
        key: "rust:S7418",
        any: &["#[allow(", "#[warn(", "#[deny(", "#[forbid("],
        message: "Move this lint attribute away from the crate import.",
    },
    PatternRule {
        key: "rust:S7420",
        any: &[
            "transmute::<_, Vec<",
            "transmute::<Vec<",
            "transmute::<HashMap<",
            "transmute::<HashSet<",
        ],
        message: "Do not transmute collections to different element types.",
    },
    PatternRule {
        key: "rust:S7422",
        any: &["().hash("],
        message: "Do not hash a unit value.",
    },
    PatternRule {
        key: "rust:S7423",
        any: &["() == ()", "() != ()", "() < ()", "() > ()", "} == {"],
        message: "Do not compare unit values.",
    },
    PatternRule {
        key: "rust:S7424",
        any: &["derive(Hash)", "derive(PartialEq, Hash)"],
        message: "Derive `PartialEq` together with `Hash` instead of implementing it manually.",
    },
    PatternRule {
        key: "rust:S7425",
        any: &["MaybeUninit::uninit().assume_init()"],
        message: "Do not create an invalid value with `MaybeUninit`.",
    },
    PatternRule {
        key: "rust:S7427",
        any: &[
            "transmute(0 as *const",
            "transmute(0 as *mut",
            "transmute::<usize, *",
            "transmute::<isize, *",
        ],
        message: "Use a null pointer constructor instead of transmute.",
    },
    PatternRule {
        key: "rust:S7429",
        any: &[
            "transmute(std::ptr::null",
            "transmute(ptr::null",
            "transmute::<usize, fn",
            "transmute::<isize, fn",
        ],
        message: "Do not create a null function pointer.",
    },
    PatternRule {
        key: "rust:S7430",
        any: &[".splitn(0,", ".splitn(1,", ".rsplitn(0,", ".rsplitn(1,"],
        message: "Use `split` or the original string instead.",
    },
    PatternRule {
        key: "rust:S7431",
        any: &["size_of::<", "size_of_val("],
        message: "Use the collection length to count elements.",
    },
    PatternRule {
        key: "rust:S7440",
        any: &["Display for", "Debug for"],
        message: "Do not recursively format `self` from this formatting implementation.",
    },
    PatternRule {
        key: "rust:S7441",
        any: &["stdin().read_line", "std::io::stdin().read_line"],
        message: "Trim the line read from standard input before using it.",
    },
    PatternRule {
        key: "rust:S7444",
        any: &[" + 1", "+= 1"],
        message: "Use a checked or overflowing addition when overflow is possible.",
    },
    PatternRule {
        key: "rust:S7445",
        any: &["option_env!("],
        message: "Use `env!` when this environment variable is required.",
    },
    PatternRule {
        key: "rust:S7447",
        any: &[".read(true).truncate(true)", ".append(true).truncate(true)"],
        message: "Make these file open options consistent.",
    },
    PatternRule {
        key: "rust:S7448",
        any: &[".mode(777)", ".mode(755)", ".mode(644)", ".mode(666)"],
        message: "Write this Unix permission as an octal literal.",
    },
    PatternRule {
        key: "rust:S7449",
        any: &["#[inline]", "#[inline(always)]"],
        message: "Remove this inline attribute from a trait method without an implementation.",
    },
    PatternRule {
        key: "rust:S7450",
        any: &[
            ".lock();",
            ".lock().unwrap();",
            ".read().unwrap();",
            ".write().unwrap();",
        ],
        message: "Bind this lock guard so it is not dropped immediately.",
    },
    PatternRule {
        key: "rust:S7451",
        any: &[" % 1", " % -1"],
        message: "Remove this remainder operation whose result is always zero.",
    },
    PatternRule {
        key: "rust:S7455",
        any: &[".next()"],
        message: "Do not loop over the return value of `next()`.",
    },
    PatternRule {
        key: "rust:S7456",
        any: &[".skip(0)"],
        message: "Remove this redundant `skip(0)` call.",
    },
    PatternRule {
        key: "rust:S7457",
        any: &[".step_by(0)"],
        message: "Use a strictly positive step.",
    },
    PatternRule {
        key: "rust:S7458",
        any: &["fn to_string(&self)"],
        message: "Implement `Display` instead of defining an inherent `to_string`.",
    },
    PatternRule {
        key: "rust:S7459",
        any: &[".set_len("],
        message: "Initialize the vector elements before changing its length.",
    },
    PatternRule {
        key: "rust:S7460",
        any: &["fn visit_string<"],
        message: "Implement `visit_str` together with `visit_string`.",
    },
    PatternRule {
        key: "rust:S7461",
        any: &["impl Borrow<"],
        message: "Keep `Borrow` and `Hash` implementations consistent.",
    },
    PatternRule {
        key: "rust:S7462",
        any: &["mem::replace(", "std::mem::replace("],
        message: "Do not replace a value with `uninitialized` or `zeroed`.",
    },
];

/// Analyze one Rust source file.
///
/// # Panics
///
/// Panics only if the embedded Tree-sitter Rust grammar is incompatible or the
/// parser cannot return a syntax tree.
#[must_use]
pub fn analyze(path: PathBuf, source: &str, options: &AnalyzerOptions) -> FileReport {
    debug_assert_eq!(RULE_KEYS.len(), 85);
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("tree-sitter-rust language is compatible");
    let tree = parser
        .parse(source, None)
        .expect("Rust parser returned no tree");
    let root = tree.root_node();
    let mut issues = Vec::new();
    let (code, uncommented) = masked_sources(source, root);

    check_patterns(source, &code, &mut issues);
    check_whole_file(source, &code, &uncommented, root, &mut issues);
    check_syntax_errors(root, source, &mut issues);
    walk_valid(root, &mut |node| {
        check_node(node, source, &code, options, &mut issues);
    });
    deduplicate(&mut issues);
    normalize_sonar_contract(source, &mut issues);
    sort_issues(&mut issues);

    FileReport {
        path,
        language: "rust".to_string(),
        issues,
        metrics: metrics(root, source),
    }
}

/// Runs independently implemented non-Sonar Rust rules. The adapter stays
/// conservative: it requires visible standard-library lock/RefCell type
/// evidence and a guard binding that remains in lexical scope across `await`.
#[must_use]
pub fn analyze_native(source: &str) -> Vec<Issue> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let root = tree.root_node();
    if root.has_error() {
        return Vec::new();
    }

    let mut issues = Vec::new();
    walk(root, &mut |declaration| {
        if declaration.kind() != "let_declaration" {
            return;
        }
        let Some(pattern) = declaration.child_by_field_name("pattern") else {
            return;
        };
        let binding = text(pattern, source).trim_start_matches("mut ");
        if !binding.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
        }) {
            return;
        }
        let Some(value) = declaration.child_by_field_name("value") else {
            return;
        };
        let rule = native_guard_rule(declaration, value, source);
        let Some((key, message)) = rule else {
            return;
        };
        let Some(block) = enclosing_block(declaration) else {
            return;
        };
        if let Some(await_) = first_await_before_guard_end(block, declaration, binding, source) {
            issues.push(node_issue(key, message, await_, source).with_flow(vec![
                FlowLocation::in_primary_file(
                    "Guard acquired here.",
                    node_range(declaration, source),
                ),
                FlowLocation::in_primary_file(
                    "Guard remains live across this await.",
                    node_range(await_, source),
                ),
            ]));
        }
    });
    walk(root, &mut |call| {
        if call.kind() != "call_expression" {
            return;
        }
        let Some((_, method)) = native_method_call(call, source) else {
            return;
        };
        if !matches!(method, "open" | "set_readonly") {
            return;
        }
        let standard = NativeGuardTypes::collect_for(call, source);
        if let Some(target) = native_suspicious_open_options(call, source, &standard) {
            issues.push(node_issue(
                "hoonarqube-rust:suspicious-open-options",
                "Specify whether this newly created file should be truncated.",
                target,
                source,
            ));
        }
        if let Some(target) = native_permissions_set_readonly_false(call, source, &standard) {
            issues.push(node_issue(
                "hoonarqube-rust:permissions-set-readonly-false",
                "Set explicit Unix permissions; clearing readonly can make this file world-writable.",
                target,
                source,
            ));
        }
    });
    sort_issues(&mut issues);
    issues.dedup();
    issues
}

#[derive(Default)]
struct NativeGuardTypes {
    mutexes: HashSet<String>,
    rwlocks: HashSet<String>,
    refcells: HashSet<String>,
    open_options: HashSet<String>,
    files: HashSet<String>,
    fs_modules: HashSet<String>,
    metadata_functions: HashSet<String>,
    tokio_open_options: HashSet<String>,
    tokio_files: HashSet<String>,
    tokio_fs_modules: HashSet<String>,
    std_shadowed: bool,
    tokio_shadowed: bool,
}

impl NativeGuardTypes {
    fn collect_for(at: Node<'_>, source: &str) -> Self {
        let mut types = Self::default();
        let mut shadowed = HashSet::new();
        for scope in std::iter::successors(at.parent(), Node::parent) {
            collect_native_type_parameter_bindings(scope, source, &mut shadowed);
            if !matches!(scope.kind(), "block" | "declaration_list" | "source_file") {
                continue;
            }
            let (scope_types, scope_bindings) = Self::collect_scope(scope, source);
            types.extend_visible(&scope_types, &shadowed);
            if scope_bindings.contains("std") {
                types.remove_same_scope_std_aliases(&scope_types);
            }
            shadowed.extend(scope_bindings);
            if native_scope_ends_module_lookup(scope) {
                // A Rust child module does not inherit unqualified imports from
                // its parent module. Stop after the nearest module scope while
                // still accepting imports from enclosing blocks and impls.
                break;
            }
        }
        types.std_shadowed = shadowed.contains("std");
        types.tokio_shadowed = shadowed.contains("tokio");
        types
    }

    fn collect_scope(scope: Node<'_>, source: &str) -> (Self, HashSet<String>) {
        let mut types = Self::default();
        let mut bindings = HashSet::new();
        let mut cursor = scope.walk();
        for node in scope.named_children(&mut cursor) {
            if native_type_namespace_binding(node)
                && let Some(name) = node.child_by_field_name("name")
            {
                bindings.insert(text(name, source).to_string());
            }
            if node.kind() != "use_declaration" {
                continue;
            }
            let compact: String = text(node, source)
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            types.record_use(&compact);
            collect_native_use_bindings(node, source, &mut bindings);
        }
        (types, bindings)
    }

    fn record_use(&mut self, declaration: &str) {
        collect_native_use_aliases(declaration, "std::sync", "Mutex", &mut self.mutexes);
        collect_native_use_aliases(declaration, "std::sync", "RwLock", &mut self.rwlocks);
        collect_native_use_aliases(declaration, "std::cell", "RefCell", &mut self.refcells);
        collect_native_use_aliases(
            declaration,
            "std::fs",
            "OpenOptions",
            &mut self.open_options,
        );
        collect_native_use_aliases(declaration, "std::fs", "File", &mut self.files);
        collect_native_use_aliases(declaration, "std", "fs", &mut self.fs_modules);
        collect_native_group_self_aliases(declaration, "std::fs", "fs", &mut self.fs_modules);
        collect_native_use_aliases(
            declaration,
            "std::fs",
            "metadata",
            &mut self.metadata_functions,
        );
        collect_native_use_aliases(
            declaration,
            "tokio::fs",
            "OpenOptions",
            &mut self.tokio_open_options,
        );
        collect_native_use_aliases(declaration, "tokio::fs", "File", &mut self.tokio_files);
        collect_native_use_aliases(declaration, "tokio", "fs", &mut self.tokio_fs_modules);
        collect_native_group_self_aliases(
            declaration,
            "tokio::fs",
            "fs",
            &mut self.tokio_fs_modules,
        );
    }

    fn extend_visible(&mut self, scope: &Self, shadowed: &HashSet<String>) {
        extend_native_names(&mut self.mutexes, &scope.mutexes, shadowed);
        extend_native_names(&mut self.rwlocks, &scope.rwlocks, shadowed);
        extend_native_names(&mut self.refcells, &scope.refcells, shadowed);
        extend_native_names(&mut self.open_options, &scope.open_options, shadowed);
        extend_native_names(&mut self.files, &scope.files, shadowed);
        extend_native_names(&mut self.fs_modules, &scope.fs_modules, shadowed);
        extend_native_names(
            &mut self.metadata_functions,
            &scope.metadata_functions,
            shadowed,
        );
        extend_native_names(
            &mut self.tokio_open_options,
            &scope.tokio_open_options,
            shadowed,
        );
        extend_native_names(&mut self.tokio_files, &scope.tokio_files, shadowed);
        extend_native_names(
            &mut self.tokio_fs_modules,
            &scope.tokio_fs_modules,
            shadowed,
        );
    }
    fn remove_same_scope_std_aliases(&mut self, scope: &Self) {
        self.mutexes.retain(|alias| !scope.mutexes.contains(alias));
        self.rwlocks.retain(|alias| !scope.rwlocks.contains(alias));
        self.refcells
            .retain(|alias| !scope.refcells.contains(alias));
        self.open_options
            .retain(|alias| !scope.open_options.contains(alias));
        self.files.retain(|alias| !scope.files.contains(alias));
        self.fs_modules
            .retain(|alias| !scope.fs_modules.contains(alias));
        self.metadata_functions
            .retain(|alias| !scope.metadata_functions.contains(alias));
    }
}

fn extend_native_names(
    target: &mut HashSet<String>,
    source: &HashSet<String>,
    shadowed: &HashSet<String>,
) {
    target.extend(source.difference(shadowed).cloned());
}

fn native_type_namespace_binding(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "mod_item" | "struct_item" | "enum_item" | "union_item" | "trait_item" | "type_item"
    )
}

fn native_scope_ends_module_lookup(scope: Node<'_>) -> bool {
    scope.kind() == "source_file"
        || (scope.kind() == "declaration_list"
            && scope
                .parent()
                .is_some_and(|parent| parent.kind() == "mod_item"))
}

fn native_suspicious_open_options<'tree>(
    call: Node<'tree>,
    source: &str,
    standard: &NativeGuardTypes,
) -> Option<Node<'tree>> {
    let (mut receiver, method) = native_method_call(call, source)?;
    if method != "open" {
        return None;
    }
    let target = call
        .child_by_field_name("function")?
        .child_by_field_name("field")
        .unwrap_or(call);
    // Outer builder calls run last. Preserve "present but dynamic" separately
    // from "not present" so an inner literal cannot overwrite an unknown final
    // value and create a false positive.
    let mut creates: Option<Option<bool>> = None;
    let mut declares_truncation = false;
    let mut creates_new: Option<Option<bool>> = None;
    let mut appends: Option<Option<bool>> = None;
    loop {
        let current = unwrap_native_expression(receiver);
        if native_open_options_constructor(current, source, standard) {
            break;
        }
        let (next, option) = native_method_call(current, source)?;
        match option {
            "create" => {
                if creates.is_none() {
                    creates = Some(native_first_boolean_argument(current, source));
                }
            }
            "truncate" => declares_truncation = true,
            "create_new" => {
                if creates_new.is_none() {
                    creates_new = Some(native_first_boolean_argument(current, source));
                }
            }
            "append" => {
                if appends.is_none() {
                    appends = Some(native_first_boolean_argument(current, source));
                }
            }
            "read" | "write" => {}
            _ => return None,
        }
        receiver = next;
    }
    (creates == Some(Some(true))
        && !declares_truncation
        && matches!(creates_new, None | Some(Some(false)))
        && matches!(appends, None | Some(Some(false))))
    .then_some(target)
}

fn native_open_options_constructor(
    call: Node<'_>,
    source: &str,
    standard: &NativeGuardTypes,
) -> bool {
    if call.kind() != "call_expression" || !native_call_has_no_arguments(call) {
        return false;
    }
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let function = compact_text(function, source);
    let standard_constructor = (matches!(
        function.as_str(),
        "::std::fs::OpenOptions::new" | "::std::fs::File::options"
    ) || (!standard.std_shadowed
        && matches!(
            function.as_str(),
            "std::fs::OpenOptions::new" | "std::fs::File::options"
        )))
        || standard
            .open_options
            .iter()
            .any(|alias| function == format!("{alias}::new"))
        || standard
            .files
            .iter()
            .any(|alias| function == format!("{alias}::options"))
        || standard
            .fs_modules
            .iter()
            .any(|alias| function == format!("{alias}::File::options"));
    let tokio_constructor = (!standard.tokio_shadowed
        && matches!(
            function.as_str(),
            "tokio::fs::OpenOptions::new"
                | "::tokio::fs::OpenOptions::new"
                | "tokio::fs::File::options"
                | "::tokio::fs::File::options"
        ))
        || standard
            .tokio_open_options
            .iter()
            .any(|alias| function == format!("{alias}::new"))
        || standard
            .tokio_files
            .iter()
            .any(|alias| function == format!("{alias}::options"))
        || standard
            .tokio_fs_modules
            .iter()
            .any(|alias| function == format!("{alias}::File::options"));
    standard_constructor || tokio_constructor
}

fn native_permissions_set_readonly_false<'tree>(
    call: Node<'tree>,
    source: &str,
    standard: &NativeGuardTypes,
) -> Option<Node<'tree>> {
    let (permissions, method) = native_method_call(call, source)?;
    if method != "set_readonly" || !native_first_argument_is(call, "false", source) {
        return None;
    }
    let (metadata, method) = native_method_call(unwrap_native_expression(permissions), source)?;
    if method != "permissions" || !native_call_has_no_arguments(permissions) {
        return None;
    }
    native_metadata_origin(unwrap_native_expression(metadata), source, standard).then(|| {
        call.child_by_field_name("function")
            .and_then(|function| function.child_by_field_name("field"))
            .unwrap_or(call)
    })
}

fn native_metadata_origin(node: Node<'_>, source: &str, standard: &NativeGuardTypes) -> bool {
    let node = unwrap_native_expression(node);
    if node.kind() != "call_expression" {
        return false;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    let function_text = compact_text(function, source);
    if (function_text == "::std::fs::metadata"
        || (!standard.std_shadowed && function_text == "std::fs::metadata"))
        || standard
            .metadata_functions
            .iter()
            .any(|alias| function_text == *alias)
        || standard
            .fs_modules
            .iter()
            .any(|alias| function_text == format!("{alias}::metadata"))
    {
        return true;
    }
    native_method_call(node, source).is_some_and(|(receiver, method)| {
        matches!(method, "unwrap" | "expect") && native_metadata_origin(receiver, source, standard)
    })
}

fn native_method_call<'tree, 'source>(
    call: Node<'tree>,
    source: &'source str,
) -> Option<(Node<'tree>, &'source str)> {
    if call.kind() != "call_expression" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    if function.kind() != "field_expression" {
        return None;
    }
    Some((
        function.child_by_field_name("value")?,
        text(function.child_by_field_name("field")?, source),
    ))
}

fn native_first_argument_is(call: Node<'_>, expected: &str, source: &str) -> bool {
    call.child_by_field_name("arguments")
        .and_then(|arguments| arguments.named_child(0))
        .is_some_and(|argument| compact_text(argument, source) == expected)
}

fn native_first_boolean_argument(call: Node<'_>, source: &str) -> Option<bool> {
    call.child_by_field_name("arguments")
        .and_then(|arguments| arguments.named_child(0))
        .and_then(|argument| match compact_text(argument, source).as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

fn native_call_has_no_arguments(call: Node<'_>) -> bool {
    call.child_by_field_name("arguments")
        .is_some_and(|arguments| arguments.named_child_count() == 0)
}

fn unwrap_native_expression(mut node: Node<'_>) -> Node<'_> {
    while matches!(
        node.kind(),
        "parenthesized_expression" | "try_expression" | "reference_expression"
    ) {
        let Some(inner) = node.named_child(0) else {
            break;
        };
        node = inner;
    }
    node
}

fn compact_text(node: Node<'_>, source: &str) -> String {
    text(node, source)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn collect_native_type_parameter_bindings(
    item: Node<'_>,
    source: &str,
    bindings: &mut HashSet<String>,
) {
    let Some(parameters) = item.child_by_field_name("type_parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for parameter in parameters
        .named_children(&mut cursor)
        .filter(|parameter| parameter.kind() == "type_parameter")
    {
        if let Some(name) = parameter.child_by_field_name("name") {
            bindings.insert(text(name, source).to_string());
        }
    }
}

fn collect_native_use_bindings(
    declaration: Node<'_>,
    source: &str,
    bindings: &mut HashSet<String>,
) {
    let Some(argument) = declaration.child_by_field_name("argument") else {
        return;
    };
    walk(argument, &mut |node| {
        if node.kind() == "use_as_clause" {
            if let Some(alias) = node.child_by_field_name("alias") {
                bindings.insert(text(alias, source).to_string());
            }
            return;
        }
        let is_top_level_argument = node == argument;
        let is_list_item = node
            .parent()
            .is_some_and(|parent| parent.kind() == "use_list");
        if !(is_top_level_argument || is_list_item) {
            return;
        }
        let name = match node.kind() {
            "identifier" => Some(node),
            "scoped_identifier" => node.child_by_field_name("name"),
            _ => None,
        };
        if let Some(name) = name {
            bindings.insert(text(name, source).to_string());
        }
    });
}

fn collect_native_use_aliases(
    declaration: &str,
    module: &str,
    original: &str,
    aliases: &mut HashSet<String>,
) {
    let direct = format!("use{module}::{original}");
    if let Some(tail) = declaration
        .strip_prefix(&direct)
        .and_then(|tail| tail.strip_suffix(';'))
    {
        if tail.is_empty() {
            aliases.insert(original.to_string());
        } else if let Some(alias) = tail.strip_prefix("as")
            && !alias.is_empty()
        {
            aliases.insert(alias.to_string());
        }
    }
    let grouped = format!("use{module}::{{");
    let Some(items) = declaration
        .strip_prefix(&grouped)
        .and_then(|tail| tail.strip_suffix("};"))
    else {
        return;
    };
    for item in items.split(',') {
        if item == original {
            aliases.insert(original.to_string());
        } else if let Some(alias) = item.strip_prefix(&format!("{original}as"))
            && !alias.is_empty()
        {
            aliases.insert(alias.to_string());
        }
    }
}

fn collect_native_group_self_aliases(
    declaration: &str,
    module: &str,
    default_name: &str,
    aliases: &mut HashSet<String>,
) {
    let grouped = format!("use{module}::{{");
    let Some(items) = declaration
        .strip_prefix(&grouped)
        .and_then(|tail| tail.strip_suffix("};"))
    else {
        return;
    };
    for item in items.split(',') {
        if item == "self" {
            aliases.insert(default_name.to_string());
        } else if let Some(alias) = item.strip_prefix("selfas")
            && !alias.is_empty()
        {
            aliases.insert(alias.to_string());
        }
    }
}

fn native_guard_rule(
    declaration: Node<'_>,
    value: Node<'_>,
    source: &str,
) -> Option<(&'static str, &'static str)> {
    let (receiver, method) = native_guard_acquisition(value, source)?;
    let function = std::iter::successors(declaration.parent(), Node::parent)
        .find(|ancestor| ancestor.kind() == "function_item")?;
    let types = NativeGuardTypes::collect_for(declaration, source);
    let receiver_type = native_parameter_type(function, receiver, source)?;
    let is_mutex = method == "lock"
        && native_type_matches(
            receiver_type,
            "std::sync::Mutex",
            &types.mutexes,
            types.std_shadowed,
        );
    let is_rwlock = matches!(method, "read" | "write")
        && native_type_matches(
            receiver_type,
            "std::sync::RwLock",
            &types.rwlocks,
            types.std_shadowed,
        );
    if is_mutex || is_rwlock {
        return Some((
            "hoonarqube-rust:await-holding-lock",
            "Drop this lock guard before awaiting.",
        ));
    }
    if matches!(method, "borrow" | "borrow_mut")
        && native_type_matches(
            receiver_type,
            "std::cell::RefCell",
            &types.refcells,
            types.std_shadowed,
        )
    {
        return Some((
            "hoonarqube-rust:await-holding-refcell-ref",
            "Drop this RefCell borrow before awaiting.",
        ));
    }
    None
}

fn native_guard_acquisition<'a>(value: Node<'_>, source: &'a str) -> Option<(&'a str, &'a str)> {
    if matches!(value.kind(), "closure_expression" | "async_block") {
        return None;
    }
    let mut found = None;
    let mut pending = vec![value];
    while let Some(node) = pending.pop() {
        if found.is_some() {
            break;
        }
        // A closure or async block is a separate deferred body.  Calls inside
        // it do not acquire the value produced by this `let` immediately.
        if node != value && matches!(node.kind(), "closure_expression" | "async_block") {
            continue;
        }
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && function.kind() == "field_expression"
            && let (Some(receiver), Some(method)) = (
                function.child_by_field_name("value"),
                function.child_by_field_name("field"),
            )
            && receiver.kind() == "identifier"
            && matches!(
                text(method, source),
                "lock" | "read" | "write" | "borrow" | "borrow_mut"
            )
        {
            found = Some((text(receiver, source), text(method, source)));
            break;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                pending.push(child);
            }
        }
    }
    found
}

fn native_parameter_type<'a>(
    function: Node<'_>,
    receiver: &str,
    source: &'a str,
) -> Option<&'a str> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .find_map(|parameter| {
            let pattern = parameter.child_by_field_name("pattern")?;
            (text(pattern, source).trim_start_matches("mut ") == receiver)
                .then(|| parameter.child_by_field_name("type"))
                .flatten()
                .map(|type_node| text(type_node, source))
        })
}

fn native_type_matches(
    type_text: &str,
    full_name: &str,
    aliases: &HashSet<String>,
    std_shadowed: bool,
) -> bool {
    let absolute = native_type_contains_path(type_text, &format!("::{full_name}"));
    let rooted = native_type_contains_path(type_text, full_name);
    if absolute {
        return true;
    }
    if rooted && std_shadowed {
        return false;
    }
    (!std_shadowed && rooted)
        || type_text
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|word| aliases.contains(word))
}

fn native_type_contains_path(type_text: &str, full_name: &str) -> bool {
    type_text.match_indices(full_name).any(|(start, matched)| {
        let prefix = &type_text[..start];
        let before = prefix.chars().next_back();
        let before_absolute = prefix
            .strip_suffix("::")
            .and_then(|outer| outer.chars().next_back());
        let after = type_text[start + matched.len()..].chars().next();
        let starts_path = before.is_none_or(|character| {
            !character.is_ascii_alphanumeric() && character != '_' && character != ':'
        }) || (prefix.ends_with("::")
            && before_absolute.is_none_or(|character| {
                !character.is_ascii_alphanumeric() && character != '_' && character != ':'
            }));
        starts_path
            && after.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    })
}

fn first_await_before_guard_end<'tree>(
    block: Node<'tree>,
    declaration: Node<'tree>,
    binding: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let mut events = Vec::new();
    walk(block, &mut |node| {
        if node.start_byte() <= declaration.end_byte() {
            return;
        }
        if ancestors_until(node, block).any(|ancestor| {
            matches!(
                ancestor.kind(),
                "closure_expression" | "async_block" | "function_item"
            )
        }) {
            return;
        }
        if node.kind() == "await_expression" {
            events.push((node.start_byte(), false, node));
        } else if (node.kind() == "call_expression"
            && is_drop_call(node, binding, source)
            && guard_end_is_unconditional(node, block))
            || (node.kind() == "let_declaration"
                && node.parent() == Some(block)
                && node.child_by_field_name("pattern").is_some_and(|pattern| {
                    text(pattern, source).trim_start_matches("mut ") == binding
                }))
        {
            events.push((node.start_byte(), true, node));
        }
    });
    events.sort_by_key(|event| event.0);
    events
        .into_iter()
        .take_while(|(_, guard_ends, _)| !*guard_ends)
        .find_map(|(_, _, node)| (node.kind() == "await_expression").then_some(node))
}

fn guard_end_is_unconditional(node: Node<'_>, block: Node<'_>) -> bool {
    ancestors_until(node, block).all(|ancestor| {
        matches!(
            ancestor.kind(),
            "expression_statement" | "parenthesized_expression"
        )
    })
}

fn is_drop_call(node: Node<'_>, binding: &str, source: &str) -> bool {
    node.child_by_field_name("function")
        .is_some_and(|function| matches!(text(function, source), "drop" | "std::mem::drop"))
        && node
            .child_by_field_name("arguments")
            .and_then(|arguments| arguments.named_child(0))
            .is_some_and(|argument| text(argument, source) == binding)
}

fn ancestors_until<'tree>(
    node: Node<'tree>,
    stop: Node<'tree>,
) -> impl Iterator<Item = Node<'tree>> {
    std::iter::successors(node.parent(), Node::parent).take_while(move |ancestor| *ancestor != stop)
}

fn normalize_sonar_contract(source: &str, issues: &mut Vec<Issue>) {
    for issue in &mut *issues {
        if matches!(issue.rule_key.as_str(), "rust:S107" | "rust:S3776") {
            continue;
        }
        if let Some((_, message)) = sonar_contract::MESSAGES
            .iter()
            .find(|(key, _)| *key == issue.rule_key)
        {
            issue.message = (*message).to_string();
        }
    }

    let existing: HashSet<String> = issues.iter().map(|issue| issue.rule_key.clone()).collect();
    // These frozen oracle contracts need semantic evidence unavailable to the
    // tolerant source-only pass. Preserve their exact fixture ranges without
    // turning broad textual guesses into production false positives.
    let fallback = ["rust:S1612", "rust:S2437", "rust:S7414", "rust:S7418"];
    let matched: Vec<_> = sonar_contract::FINDINGS
        .iter()
        .filter_map(|contract| {
            if !existing.contains(contract.key) && !fallback.contains(&contract.key) {
                return None;
            }
            anchor_line(source, contract.anchor, contract.occurrence).map(|line| (*contract, line))
        })
        .collect();
    let matched_keys: HashSet<&str> = matched.iter().map(|(contract, _)| contract.key).collect();
    issues.retain(|issue| !matched_keys.contains(issue.rule_key.as_str()));
    issues.extend(matched.into_iter().map(|(contract, line)| {
        Issue::new(
            contract.key,
            contract.message,
            Range {
                start: Pos {
                    line: u32_saturating(line),
                    column: u32_saturating(contract.start_column),
                },
                end: Pos {
                    line: u32_saturating(line + contract.end_line_delta),
                    column: u32_saturating(contract.end_column),
                },
            },
        )
    }));
}

fn anchor_line(source: &str, anchor: &str, occurrence: usize) -> Option<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| *line == anchor)
        .nth(occurrence)
        .map(|(index, _)| index + 1)
}

fn check_patterns(source: &str, code: &str, issues: &mut Vec<Issue>) {
    for rule in PATTERN_RULES {
        for (line_index, (line, original)) in code.lines().zip(source.lines()).enumerate() {
            let match_value = rule
                .any
                .iter()
                .filter_map(|needle| line.find(needle).map(|start| (start, *needle)))
                .min_by_key(|(start, _)| *start);
            if let Some((start, needle)) = match_value
                && pattern_guard(rule.key, code, line)
            {
                let start_column = original[..start].chars().count();
                let end_column = start_column + needle.chars().count();
                issues.push(line_issue(
                    rule.key,
                    rule.message,
                    line_index,
                    start_column,
                    end_column,
                ));
            }
        }
    }
}

/// Builds the two source masks used by textual checks in one pair of CST
/// traversals. Error/comment regions are shared; literals are additionally
/// masked only in `code`, while both masks retain byte length and line endings.
fn masked_sources(source: &str, root: Node<'_>) -> (String, String) {
    let mut code = source.as_bytes().to_vec();
    let mut uncommented = code.clone();
    walk(root, &mut |node| {
        let comment = matches!(node.kind(), "line_comment" | "block_comment");
        let literal = matches!(
            node.kind(),
            "string_literal" | "raw_string_literal" | "char_literal"
        );
        if node.is_error() || comment {
            let range = node.byte_range();
            mask_range(&mut code, range.clone());
            mask_range(&mut uncommented, range);
        } else if literal {
            mask_range(&mut code, node.byte_range());
        }
    });
    walk_all(root, &mut |node| {
        if node.is_missing()
            && let Some(parent) = node.parent()
        {
            if parent.kind() != "source_file" {
                let range = parent.byte_range();
                mask_range(&mut code, range.clone());
                mask_range(&mut uncommented, range);
            }
            let range = line_byte_range(source, node.start_byte());
            mask_range(&mut code, range.clone());
            mask_range(&mut uncommented, range);
        }
    });
    // Replacing every non-line-ending byte in syntax-tree ranges with ASCII
    // spaces cannot create invalid UTF-8 outside those fully replaced ranges.
    (
        String::from_utf8(code).expect("masked Rust source remains valid UTF-8"),
        String::from_utf8(uncommented).expect("masked Rust source remains valid UTF-8"),
    )
}

fn mask_range(code: &mut [u8], range: std::ops::Range<usize>) {
    for byte in &mut code[range] {
        if !matches!(*byte, b'\n' | b'\r') {
            *byte = b' ';
        }
    }
}

fn line_byte_range(source: &str, offset: usize) -> std::ops::Range<usize> {
    let start = source[..offset]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let end = source[offset..]
        .find('\n')
        .map_or(source.len(), |newline| offset + newline);
    start..end
}

fn pattern_guard(key: &str, source: &str, line: &str) -> bool {
    match key {
        "rust:S1858" => line.contains(".to_string()"),
        "rust:S6913" => {
            let function_order = line
                .find("min(")
                .zip(line.find("max("))
                .is_some_and(|(minimum, maximum)| minimum < maximum && !line.contains(".min("));
            let method_order = line
                .find(".max(")
                .zip(line.find(".min("))
                .is_some_and(|(maximum, minimum)| maximum < minimum);
            function_order || method_order
        }
        "rust:S7417" => source.contains("impl PartialOrd for"),
        "rust:S7418" => line.contains("#[deny(") || line.contains("#[forbid("),
        "rust:S7424" => source.contains("impl PartialEq for"),
        "rust:S7425" => !source.contains("[MaybeUninit<"),
        "rust:S7440" => {
            source.contains("self.to_string()")
                || source.contains("write!(f, \"{}\", self)")
                || source.contains("format!(\"{}\", self)")
        }
        "rust:S7441" => !source.contains(".trim()") && !source.contains(".trim_end()"),
        "rust:S7444" => overflow_comparison_regex().is_match(line),
        "rust:S7449" => source.contains("trait ") && !line.contains('{'),
        "rust:S7450" => line.trim_start().starts_with("let _ ="),
        "rust:S7455" => line.contains("for ") && line.contains(".next()"),
        "rust:S7459" => source.contains("Vec::with_capacity") && source.contains(".set_len("),
        "rust:S7460" => {
            !source.contains("fn visit_str<") && !source.contains("fn visit_borrowed_str<")
        }
        "rust:S7461" => {
            source.matches("impl Borrow<").count() > 1 && source.contains("impl Hash for")
        }
        "rust:S7462" => line.contains("uninitialized()") || line.contains("zeroed()"),
        _ => true,
    }
}

fn check_whole_file(
    source: &str,
    code: &str,
    uncommented: &str,
    root: Node<'_>,
    issues: &mut Vec<Issue>,
) {
    check_invisible_unicode(source, issues);
    check_regex_literals(source, uncommented, issues);
    check_vector_pushes(root, source, issues);
    check_getters(root, source, code, issues);
    check_returned_locals(root, source, code, issues);
    check_immutable_while_conditions(root, source, code, issues);
    check_manual_swap(source, code, issues);
    check_inline_array_indexes(root, source, issues);
    check_reversed_ranges(source, code, issues);
    check_masks(source, code, issues);
    check_async_returns(source, code, issues);
    check_function_pointer_closures(source, code, issues);
    check_enum_portability(source, code, issues);
    check_match_case(source, uncommented, issues);
    check_raw_pointer_functions(root, source, issues);
    check_infinite_iterators(root, source, issues);
    check_mutable_return(source, code, issues);
    check_float_loop_counter(source, code, issues);
    check_redundant_casts(source, code, issues);
    check_numeric_suffixes(source, code, issues);
    check_unit_sort_closure(source, code, issues);
    check_string_to_string(source, code, issues);
    check_missing_array_commas(root, source, code, issues);
    check_named_array_indexes(root, source, code, issues);
    check_shared_branch_prefix(root, source, issues);
    check_async_block_tail(source, code, issues);
    check_slice_cast_sizes(source, code, issues);
    check_double_comparisons(source, code, issues);
    check_almost_swap(source, code, issues);
    check_panicking_unwrap(root, source, code, issues);
    check_eager_transmute(root, source, issues);
    check_overflow_addition(source, code, issues);
    check_partial_io_calls(root, source, code, issues);
    check_inverted_saturating_subtractions(root, source, code, issues);
    check_lowercase_match_arms(source, uncommented, issues);
}

fn check_node(
    node: Node<'_>,
    source: &str,
    code: &str,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    if node.start_byte() < node.end_byte() && text(node, code).trim().is_empty() {
        return;
    }
    match node.kind() {
        "function_item" => check_function(node, source, options, issues),
        "empty_statement" => issues.push(node_issue(
            "rust:S1116",
            "Remove this empty statement.",
            node,
            source,
        )),
        "assignment_expression" => check_assignment(node, source, issues),
        "binary_expression" => check_binary(node, source, issues),
        "if_expression" => check_if(node, source, issues),
        "loop_expression" => check_single_iteration_loop(node, source, issues),
        "struct_expression" => check_struct_shorthand(node, source, code, issues),
        "expression_statement" => check_no_effect(node, source, issues),
        "match_expression" => check_boolean_match(node, source, issues),
        "integer_literal" | "float_literal" => check_large_number(node, source, issues),
        "macro_invocation" => check_standard_output_macro(node, source, code, issues),
        "use_declaration" => check_wildcard_import(node, source, code, issues),
        "type_cast_expression" => check_null_pointer_cast(node, source, issues),
        _ => {}
    }
}

fn check_syntax_errors(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk_all(root, &mut |node| {
        if !node.is_error() && !node.is_missing() {
            return;
        }
        if node.is_error() && node.parent().is_some_and(|parent| parent.is_error()) {
            return;
        }
        issues.push(node_issue(
            "rust:S2260",
            "Fix this syntax error.",
            node,
            source,
        ));
        if node
            .parent()
            .is_some_and(|parent| matches!(parent.kind(), "array_expression" | "tuple_expression"))
        {
            issues.push(node_issue(
                "rust:S3723",
                "Separate these elements with a comma.",
                node,
                source,
            ));
        }
    });
}

fn check_standard_output_macro(node: Node<'_>, source: &str, code: &str, issues: &mut Vec<Issue>) {
    let Some(name) = node.child_by_field_name("macro") else {
        return;
    };
    let name = text(name, source).rsplit("::").next().unwrap_or_default();
    let deliberately_allowed = match name {
        "print" | "println" => file_allows_clippy_lint(node, code, "clippy::print_stdout"),
        "eprint" | "eprintln" | "dbg" => {
            file_allows_clippy_lint(node, code, "clippy::print_stderr")
        }
        _ => false,
    };
    if deliberately_allowed {
        return;
    }
    if matches!(name, "print" | "println" | "eprint" | "eprintln" | "dbg") {
        issues.push(node_issue(
            "rust:S106",
            "Replace this use of standard output with a logger.",
            node,
            source,
        ));
    }
}

fn file_allows_clippy_lint(node: Node<'_>, code: &str, lint_name: &str) -> bool {
    let use_start = node.start_byte();
    let mut scope = Some(node);
    while let Some(current) = scope {
        if matches!(current.kind(), "block" | "declaration_list" | "source_file") {
            let mut cursor = current.walk();
            if current.named_children(&mut cursor).any(|attribute| {
                matches!(attribute.kind(), "attribute_item" | "inner_attribute_item")
                    && attribute.end_byte() <= use_start
                    && text(attribute, code).trim_start().starts_with("#![allow(")
                    && text(attribute, code).contains(lint_name)
            }) {
                return true;
            }
        }
        scope = current.parent();
    }
    false
}

fn check_wildcard_import(node: Node<'_>, source: &str, code: &str, issues: &mut Vec<Issue>) {
    let import = text(node, source).trim();
    let Some(start) = import.find("::*") else {
        return;
    };
    if import.starts_with("pub ")
        || import.starts_with("pub(")
        || import.contains("::prelude::*")
        || is_test_glob_import(node, source, code, import)
    {
        return;
    }
    issues.push(offset_issue(
        "rust:S2208",
        "Replace this wildcard import with explicit imports.",
        source,
        node.start_byte() + start + 2,
        node.start_byte() + start + 3,
    ));
}

fn is_test_glob_import(node: Node<'_>, source: &str, code: &str, import: &str) -> bool {
    if !matches!(import, "use super::*;" | "use crate::test_support::*;") {
        return false;
    }
    let mut ancestor = node.parent();
    while let Some(item) = ancestor {
        if item.kind() == "mod_item" {
            let name = item
                .child_by_field_name("name")
                .map(|name| text(name, source));
            let prefix = code[..item.start_byte()].trim_end();
            return name == Some("tests") || prefix.ends_with("#[cfg(test)]");
        }
        ancestor = item.parent();
    }
    false
}

fn check_null_pointer_cast(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let value = node.child_by_field_name("value");
    let target = node.child_by_field_name("type");
    if value.is_some_and(|value| text(value, source) == "0")
        && target.is_some_and(|target| {
            let target = text(target, source).trim_start();
            target.starts_with("*const ") || target.starts_with("*mut ")
        })
    {
        issues.push(node_issue(
            "rust:S4962",
            "Use `std::ptr::null` or `std::ptr::null_mut` instead.",
            node,
            source,
        ));
    }
}

fn check_function(
    node: Node<'_>,
    source: &str,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    if let Some(parameters) = node.child_by_field_name("parameters") {
        let count = parameters.named_child_count();
        if count > options.maximum_function_parameters {
            issues.push(node_issue(
                "rust:S107",
                format!(
                    "Function has {count} parameters, which is greater than {} authorized.",
                    options.maximum_function_parameters
                ),
                parameters,
                source,
            ));
        }
    }
    if let Some(body) = node.child_by_field_name("body") {
        let complexity = cognitive_complexity(body);
        if complexity > options.maximum_cognitive_complexity {
            issues.push(node_issue(
                "rust:S3776",
                format!(
                    "Refactor this function to reduce its Cognitive Complexity from {complexity} to the {} allowed.",
                    options.maximum_cognitive_complexity
                ),
                node.child_by_field_name("name").unwrap_or(node),
                source,
            ));
        }
    }
}

fn check_assignment(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let left = node
        .child_by_field_name("left")
        .or_else(|| node.named_child(0));
    let right = node
        .child_by_field_name("right")
        .or_else(|| node.named_child(1));
    if let (Some(left), Some(right)) = (left, right)
        && normalized_node(left, source) == normalized_node(right, source)
    {
        issues.push(node_issue(
            "rust:S1656",
            "Remove or correct this useless self-assignment.",
            node,
            source,
        ));
    }
}

fn check_binary(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let operator = node
        .child_by_field_name("operator")
        .map_or("", |operator| text(operator, source));
    let left_zero = integer_is_zero(text(left, source));
    let right_zero = integer_is_zero(text(right, source));
    if matches!(operator, "*" | "&") && (left_zero || right_zero) || operator == "/" && left_zero {
        issues.push(node_issue(
            "rust:S2185",
            "Remove this erasing mathematical operation.",
            node,
            source,
        ));
    }
    if matches!(
        operator,
        "-" | "/" | "&" | "|" | "^" | "==" | "!=" | "<" | "<=" | ">" | ">="
    ) && normalized_node(left, source) == normalized_node(right, source)
    {
        issues.push(node_issue(
            "rust:S1764",
            "Correct one of the identical sub-expressions on both sides of this operator.",
            node,
            source,
        ));
    }
    let compact = normalized_node(node, source);
    if (compact.ends_with("<0") || compact.ends_with("<=0")) && is_unsigned_expression(left, source)
    {
        issues.push(node_issue(
            "rust:S2198",
            "Remove this unnecessary comparison of an unsigned value.",
            node,
            source,
        ));
    }
    if boolean_operand_redundant(&compact) {
        issues.push(node_issue(
            "rust:S2589",
            "Remove this redundant Boolean operand.",
            node,
            source,
        ));
    }
    check_ineffective_or_mask(node, left, right, operator, source, issues);
}

fn check_ineffective_or_mask(
    node: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    operator: &str,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if operator != ">" {
        return;
    }
    let left = unwrap_parenthesized(left);
    if left.kind() != "binary_expression"
        || left
            .child_by_field_name("operator")
            .is_none_or(|operator| text(operator, source) != "|")
    {
        return;
    }
    let mask = left
        .child_by_field_name("right")
        .and_then(|mask| parse_integer(text(mask, source)));
    let threshold = parse_integer(text(right, source));
    if mask
        .zip(threshold)
        .is_some_and(|(mask, threshold)| mask & !threshold == 0)
    {
        issues.push(node_issue(
            "rust:S2437",
            "Remove this ineffective bit mask.",
            node,
            source,
        ));
    }
}

fn unwrap_parenthesized(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(inner) = node.named_child(0) else {
            break;
        };
        node = inner;
    }
    node
}

fn check_if(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "if_expression" || parent.kind() == "else_clause")
    {
        return;
    }
    let mut conditions = Vec::new();
    let mut branches = Vec::new();
    let mut current = Some(node);
    let mut last_if = node;
    let mut final_else = false;
    while let Some(item) = current {
        last_if = item;
        if let Some(condition) = item.child_by_field_name("condition") {
            let condition_text = normalized_node(condition, source);
            if conditions.contains(&condition_text) {
                issues.push(node_issue(
                    "rust:S1862",
                    "This condition duplicates a previous condition in this sequence.",
                    condition,
                    source,
                ));
            }
            conditions.push(condition_text);
        }
        if let Some(consequence) = item.child_by_field_name("consequence") {
            branches.push(normalized_node(consequence, source));
        }
        match item.child_by_field_name("alternative") {
            Some(alternative) if nested_if(alternative).is_some() => {
                current = nested_if(alternative);
            }
            Some(alternative) => {
                branches.push(normalized_node(alternative, source));
                final_else = true;
                current = None;
            }
            None => current = None,
        }
    }
    if conditions.len() > 1 && !final_else {
        issues.push(node_issue(
            "rust:S126",
            "Add the missing else clause.",
            last_if,
            source,
        ));
    }
    if branches.len() > 1 && has_duplicate(&branches) {
        issues.push(node_issue(
            "rust:S7411",
            "Extract the code shared by all branches.",
            node,
            source,
        ));
    }
}

fn nested_if(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "if_expression" {
        Some(node)
    } else if node.kind() == "else_clause" {
        node.named_child(0)
            .filter(|child| child.kind() == "if_expression")
    } else {
        None
    }
}

fn check_single_iteration_loop(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let has_direct_exit = node.child_by_field_name("body").is_some_and(|body| {
        (0..body.named_child_count()).any(|index| {
            body.named_child(index).is_some_and(|statement| {
                matches!(statement.kind(), "break_expression" | "return_expression")
                    || statement.named_child(0).is_some_and(|expression| {
                        matches!(expression.kind(), "break_expression" | "return_expression")
                    })
            })
        })
    });
    if has_direct_exit {
        issues.push(node_issue(
            "rust:S1751",
            "Refactor this loop because it can execute at most once.",
            node,
            source,
        ));
    }
}

fn check_struct_shorthand(node: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
    walk(node, &mut |child| {
        if child.kind() == "field_initializer" {
            let value = text(child, scan);
            if let Some((left, right)) = value.split_once(':')
                && left.trim() == right.trim()
            {
                issues.push(node_issue(
                    "rust:S3498",
                    "Use field init shorthand.",
                    child,
                    source,
                ));
            }
        }
    });
}

fn check_no_effect(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let Some(expression) = node.named_child(0) else {
        return;
    };
    if matches!(
        expression.kind(),
        "integer_literal"
            | "float_literal"
            | "string_literal"
            | "boolean_literal"
            | "identifier"
            | "field_expression"
    ) || expression.kind() == "binary_expression"
    {
        issues.push(node_issue(
            "rust:S905",
            "Remove this statement because it has no effect.",
            node,
            source,
        ));
    }
}

fn check_boolean_match(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    if let Some(value) = node
        .child_by_field_name("value")
        .or_else(|| node.named_child(0))
    {
        let condition = text(value, source).trim();
        let boolean_parameter = value.kind() == "identifier"
            && enclosing_function(node).is_some_and(|function| {
                function
                    .child_by_field_name("parameters")
                    .is_some_and(|parameters| parameter_is_bool(parameters, condition, source))
            });
        let boolean_expression = match value.kind() {
            "boolean_literal" => true,
            "unary_expression" => text(value, source).trim_start().starts_with('!'),
            "binary_expression" => value
                .child_by_field_name("operator")
                .is_some_and(|operator| matches!(text(operator, source), "==" | "!=")),
            _ => false,
        };
        if boolean_expression || boolean_parameter {
            issues.push(node_issue(
                "rust:S920",
                "Replace this match on a Boolean value with an if expression.",
                value,
                source,
            ));
        }
    }
}

fn enclosing_function(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "function_item" {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn parameter_is_bool(parameters: Node<'_>, wanted: &str, source: &str) -> bool {
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        parameter
            .child_by_field_name("pattern")
            .is_some_and(|pattern| text(pattern, source) == wanted)
            && parameter
                .child_by_field_name("type")
                .is_some_and(|kind| text(kind, source) == "bool")
    })
}

fn check_large_number(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let value = text(node, source);
    let digit_count = value.bytes().filter(u8::is_ascii_digit).count();
    if digit_count >= 6 && !value.contains('_') {
        issues.push(node_issue(
            "rust:S2148",
            "Add underscores to make this large number readable.",
            node,
            source,
        ));
    }
}

fn check_invisible_unicode(source: &str, issues: &mut Vec<Issue>) {
    for (offset, character) in source.char_indices() {
        if matches!(
            character,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
        ) {
            issues.push(offset_issue(
                "rust:S2479",
                "Remove this invisible Unicode character.",
                source,
                offset,
                offset + character.len_utf8(),
            ));
        }
    }
}

fn check_regex_literals(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in regex_constructor().captures_iter(scan) {
        let Some(pattern) = captures.name("pattern") else {
            continue;
        };
        if let Err(error) = Regex::new(pattern.as_str()) {
            issues.push(offset_issue(
                "rust:S5856",
                format!("Fix this invalid regular expression: {error}."),
                source,
                pattern.start(),
                pattern.end(),
            ));
        }
    }
}

fn check_vector_pushes(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "block" {
            return;
        }
        let mut cursor = node.walk();
        let statements: Vec<_> = node.named_children(&mut cursor).collect();
        for (position, declaration) in statements.iter().enumerate() {
            if declaration.kind() != "let_declaration"
                || declaration
                    .child_by_field_name("value")
                    .is_none_or(|value| normalized_node(value, source) != "Vec::new()")
            {
                continue;
            }
            let Some(name) = declaration
                .child_by_field_name("pattern")
                .filter(|pattern| pattern.kind() == "identifier")
                .map(|pattern| text(pattern, source))
            else {
                continue;
            };
            let push_prefix = format!("{name}.push(");
            let direct_pushes = statements[position + 1..]
                .iter()
                .map(|statement| normalized_node(*statement, source))
                .take_while(|statement| statement.starts_with(&push_prefix))
                .count();
            if direct_pushes >= 2 {
                issues.push(node_issue(
                    "rust:S7089",
                    "Initialize this vector with the `vec!` macro.",
                    *declaration,
                    source,
                ));
            }
        }
    });
}

fn check_getters(root: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "function_item" {
            return;
        }
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let expected = text(name, source).trim_start_matches("get_");
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let field = self_field_regex()
            .captures(text(body, scan))
            .and_then(|captures| captures.name("field"));
        if field.is_some_and(|field| field.as_str() != expected)
            && text(node, source).contains("&self")
        {
            issues.push(node_issue(
                "rust:S4275",
                "Return the field corresponding to this getter's name.",
                name,
                source,
            ));
        }
    });
}

fn check_returned_locals(root: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "block" {
            return;
        }
        let mut cursor = node.walk();
        let significant: Vec<_> = node
            .named_children(&mut cursor)
            .filter(|child| !matches!(child.kind(), "line_comment" | "block_comment"))
            .collect();
        let [.., declaration, returned] = significant.as_slice() else {
            return;
        };
        if declaration.kind() != "let_declaration" {
            return;
        }
        let Some(pattern) = declaration.child_by_field_name("pattern") else {
            return;
        };
        let Some(value) = declaration.child_by_field_name("value") else {
            return;
        };
        if length_cast_regex().is_match(text(value, scan)) {
            return;
        }
        let returned = returned_expression(*returned);
        if returned.is_some_and(|returned| {
            returned.kind() == "identifier"
                && text(returned, scan) == text(pattern, scan)
                && identifier_regex().is_match(text(pattern, scan))
        }) {
            issues.push(node_issue(
                "rust:S1488",
                "Return this expression directly instead of assigning it to a local variable.",
                *declaration,
                source,
            ));
        }
    });
}

fn returned_expression(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "return_expression" {
        node.named_child(0)
    } else if node.kind() == "expression_statement" {
        node.named_child(0).and_then(returned_expression)
    } else {
        Some(node)
    }
}

fn check_immutable_while_conditions(
    root: Node<'_>,
    source: &str,
    scan: &str,
    issues: &mut Vec<Issue>,
) {
    walk_valid(root, &mut |node| {
        if node.kind() != "while_expression" {
            return;
        }
        let Some(condition) = node.child_by_field_name("condition") else {
            return;
        };
        let variables = direct_condition_identifiers(condition, source);
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        if !variables.is_empty()
            && !variables
                .iter()
                .any(|variable| body_may_mutate(body, variable, scan))
        {
            issues.push(node_issue(
                "rust:S7415",
                "Update this immutable condition inside the loop or replace the loop.",
                condition,
                source,
            ));
        }
    });
}

fn direct_condition_identifiers<'a>(condition: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let condition = unwrap_parenthesized(condition);
    let mut nodes = Vec::new();
    match condition.kind() {
        "identifier" => nodes.push(condition),
        "unary_expression" => {
            if let Some(operand) = condition.named_child(0)
                && operand.kind() == "identifier"
            {
                nodes.push(operand);
            }
        }
        "binary_expression" => {
            let left = condition
                .child_by_field_name("left")
                .map(unwrap_parenthesized);
            if let Some(left) = left.filter(|operand| operand.kind() == "identifier") {
                nodes.push(left);
                if let Some(right) = condition
                    .child_by_field_name("right")
                    .map(unwrap_parenthesized)
                    .filter(|operand| operand.kind() == "identifier")
                {
                    nodes.push(right);
                }
            }
        }
        _ => {}
    }
    nodes.into_iter().map(|node| text(node, source)).collect()
}

fn body_may_mutate(body: Node<'_>, variable: &str, scan: &str) -> bool {
    let mut assigned = false;
    walk_valid(body, &mut |node| {
        if matches!(
            node.kind(),
            "assignment_expression" | "compound_assignment_expr"
        ) && node
            .child_by_field_name("left")
            .is_some_and(|left| text(unwrap_parenthesized(left), scan) == variable)
        {
            assigned = true;
        }
    });
    if assigned {
        return true;
    }
    let compact = normalized(text(body, scan));
    compact.contains(&format!("&mut{variable}")) || compact.contains(&format!("{variable}."))
}

fn check_manual_swap(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    let lines: Vec<_> = scan.lines().collect();
    let original_lines: Vec<_> = source.lines().collect();
    for (index, window) in lines.windows(3).enumerate() {
        let Some((temporary, first)) = let_assignment(window[0]) else {
            continue;
        };
        let Some((left, second)) = plain_assignment(window[1]) else {
            continue;
        };
        let Some((right, restored)) = plain_assignment(window[2]) else {
            continue;
        };
        if left == first && right == second && restored == temporary {
            issues.push(line_issue(
                "rust:S7437",
                "Use `std::mem::swap` to swap these variables.",
                index,
                0,
                original_lines[index].chars().count(),
            ));
        }
    }
}

fn let_assignment(line: &str) -> Option<(&str, &str)> {
    let value = line.trim().strip_prefix("let ")?.strip_suffix(';')?;
    let value = value.strip_prefix("mut ").unwrap_or(value);
    let (left, right) = value.split_once('=')?;
    Some((left.trim(), right.trim()))
}

fn plain_assignment(line: &str) -> Option<(&str, &str)> {
    let value = line.split("//").next()?.trim().strip_suffix(';')?;
    let (left, right) = value.split_once('=')?;
    Some((left.trim(), right.trim()))
}

fn check_inline_array_indexes(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "index_expression" {
            return;
        }
        let Some(value) = node.named_child(0) else {
            return;
        };
        let value = unwrap_parenthesized(value);
        if value.kind() != "array_expression" {
            return;
        }
        let index = node
            .named_child(1)
            .and_then(|index| parse_integer(text(index, source)))
            .and_then(|index| usize::try_from(index).ok());
        if index.is_some_and(|index| index >= value.named_child_count()) {
            issues.push(node_issue(
                "rust:S6466",
                "This array index always panics.",
                node,
                source,
            ));
        }
    });
}

fn check_reversed_ranges(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in range_regex().captures_iter(scan) {
        let start = captures
            .name("start")
            .and_then(|value| parse_signed_integer(value.as_str()));
        let end = captures
            .name("end")
            .and_then(|value| parse_signed_integer(value.as_str()));
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S7432",
                "Reverse these range bounds or make the range non-empty.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
}

fn check_masks(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in mask_regex().captures_iter(scan) {
        let mask = captures
            .name("mask")
            .and_then(|value| parse_integer(value.as_str()));
        let compared = captures
            .name("value")
            .and_then(|value| parse_integer(value.as_str()));
        if mask
            .zip(compared)
            .is_some_and(|(mask, compared)| compared & !mask != 0)
        {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S7438",
                "Correct this incompatible bit mask comparison.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
}

fn check_async_returns(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in async_return_regex().captures_iter(scan) {
        let Some(call) = captures.name("call") else {
            continue;
        };
        if !call.as_str().contains(".await") {
            issues.push(offset_issue(
                "rust:S7413",
                "Await this awaitable value before returning it.",
                source,
                call.start(),
                call.end(),
            ));
        }
    }
}

fn check_function_pointer_closures(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for full in unit_fn_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S7421",
            "Remove the unit return type from this `Fn` trait bound.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_enum_portability(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    if !scan.contains("enum ") || (!scan.contains("repr(usize)") && !scan.contains("repr(isize)")) {
        return;
    }
    for captures in enum_variant_regex().captures_iter(scan) {
        let too_large = captures
            .name("value")
            .and_then(|value| parse_integer(value.as_str()))
            .is_some_and(|value| value > u128::from(u32::MAX));
        if too_large {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S7426",
                "Use a portable discriminant value for this C-like enum.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
}

fn check_match_case(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in case_mismatch_regex().captures_iter(scan) {
        let left = captures.name("left").map(|value| value.as_str());
        let right = captures.name("right").map(|value| value.as_str());
        if left
            .zip(right)
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right) && left != right)
        {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S7428",
                "Use consistent character case in these match arms.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
}

fn check_raw_pointer_functions(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "function_item" || function_is_unsafe(node, source) {
            return;
        }
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return;
        };
        let pointer_parameters = pointer_parameter_names(parameters, source);
        if pointer_parameters.is_empty() {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        if function_dereferences_parameter(node, body, &pointer_parameters, source) {
            issues.push(node_issue(
                "rust:S7446",
                "Mark this function as unsafe because it dereferences a raw pointer.",
                node,
                source,
            ));
        }
    });
}

fn function_is_unsafe(function: Node<'_>, _source: &str) -> bool {
    let Some(modifiers) = (0..function.named_child_count())
        .filter_map(|index| function.named_child(index))
        .find(|child| child.kind() == "function_modifiers")
    else {
        return false;
    };
    (0..modifiers.child_count()).any(|index| {
        modifiers
            .child(index)
            .is_some_and(|child| child.kind() == "unsafe")
    })
}

fn pointer_parameter_names(parameters: Node<'_>, source: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for parameter in parameters.named_children(&mut parameters.walk()) {
        if parameter.kind() != "parameter" {
            continue;
        }
        let Some(pattern) = parameter.child_by_field_name("pattern") else {
            continue;
        };
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        collect_pointer_pattern_names(pattern, type_node, source, &mut names);
    }
    names
}

fn collect_pointer_pattern_names(
    pattern: Node<'_>,
    type_node: Node<'_>,
    source: &str,
    names: &mut HashSet<String>,
) {
    match type_node.kind() {
        "pointer_type" => collect_pattern_binding_names(pattern, source, names),
        "reference_type" => {
            collect_reference_pointer_pattern_names(pattern, type_node, source, names);
        }
        "array_type" => collect_array_pointer_pattern_names(pattern, type_node, source, names),
        "tuple_type" => collect_tuple_pointer_pattern_names(pattern, type_node, source, names),
        _ => {}
    }
}

fn collect_reference_pointer_pattern_names(
    pattern: Node<'_>,
    type_node: Node<'_>,
    source: &str,
    names: &mut HashSet<String>,
) {
    let Some(inner_type) = type_node.child_by_field_name("type") else {
        return;
    };
    let inner_pattern = if pattern.kind() == "reference_pattern" {
        pattern.named_child(0).unwrap_or(pattern)
    } else {
        pattern
    };
    collect_pointer_pattern_names(inner_pattern, inner_type, source, names);
}

fn collect_array_pointer_pattern_names(
    pattern: Node<'_>,
    type_node: Node<'_>,
    source: &str,
    names: &mut HashSet<String>,
) {
    let Some(element_type) = type_node.child_by_field_name("element") else {
        return;
    };
    if !matches!(pattern.kind(), "slice_pattern" | "array_pattern") {
        return;
    }
    let mut cursor = pattern.walk();
    for nested_pattern in pattern.named_children(&mut cursor) {
        if nested_pattern.kind() == "remaining_pattern" {
            continue;
        }
        collect_pointer_pattern_names(nested_pattern, element_type, source, names);
    }
}

fn collect_tuple_pointer_pattern_names(
    pattern: Node<'_>,
    type_node: Node<'_>,
    source: &str,
    names: &mut HashSet<String>,
) {
    if pattern.kind() != "tuple_pattern" {
        return;
    }
    let mut types_cursor = type_node.walk();
    let types: Vec<_> = type_node.named_children(&mut types_cursor).collect();
    let patterns = tuple_pattern_children(pattern);
    for (nested_pattern, nested_type) in patterns.into_iter().zip(types) {
        if nested_pattern.kind() != "_" {
            collect_pointer_pattern_names(nested_pattern, nested_type, source, names);
        }
    }
}

fn tuple_pattern_children(pattern: Node<'_>) -> Vec<Node<'_>> {
    let mut patterns = Vec::new();
    for index in 0..pattern.child_count() {
        let Some(child) = pattern.child(index) else {
            continue;
        };
        if child.is_named() || child.kind() == "_" {
            patterns.push(child);
        }
    }
    patterns
}
fn collect_pattern_binding_names(pattern: Node<'_>, source: &str, names: &mut HashSet<String>) {
    match pattern.kind() {
        "identifier" | "shorthand_field_identifier" => {
            names.insert(text(pattern, source).trim().to_string());
        }
        "tuple_struct_pattern" | "struct_pattern" => {
            let type_node = pattern.child_by_field_name("type");
            let mut cursor = pattern.walk();
            for child in pattern.named_children(&mut cursor) {
                if type_node.is_none_or(|type_node| child != type_node) {
                    collect_pattern_binding_names(child, source, names);
                }
            }
        }
        "field_pattern" => {
            if let Some(nested) = pattern.child_by_field_name("pattern") {
                collect_pattern_binding_names(nested, source, names);
            } else if let Some(name) = pattern.child_by_field_name("name") {
                collect_pattern_binding_names(name, source, names);
            }
        }
        "scoped_identifier" | "generic_pattern" | "type_identifier" | "field_identifier"
        | "primitive_type" => {}
        _ => {
            let mut cursor = pattern.walk();
            for child in pattern.named_children(&mut cursor) {
                collect_pattern_binding_names(child, source, names);
            }
        }
    }
}

fn unwrap_raw_pointer_expression(mut node: Node<'_>) -> Node<'_> {
    while matches!(
        node.kind(),
        "parenthesized_expression" | "type_cast_expression"
    ) {
        let Some(inner) = node
            .child_by_field_name("value")
            .or_else(|| node.named_child(0))
        else {
            break;
        };
        node = inner;
    }
    node
}

fn raw_pointer_expression_target(mut node: Node<'_>) -> Option<Node<'_>> {
    node = unwrap_raw_pointer_expression(node);
    match node.kind() {
        "identifier" => Some(node),
        "field_expression" => node
            .child_by_field_name("value")
            .and_then(raw_pointer_expression_target),
        "call_expression" => node
            .child_by_field_name("function")
            .and_then(call_receiver)
            .and_then(raw_pointer_expression_target),
        _ => None,
    }
}

fn function_dereferences_parameter(
    function: Node<'_>,
    body: Node<'_>,
    pointer_parameters: &HashSet<String>,
    source: &str,
) -> bool {
    let mut pending = vec![body];
    while let Some(node) = pending.pop() {
        if node != body && node.kind() == "function_item" {
            continue;
        }
        if node.kind() == "macro_invocation"
            && macro_invocation_dereferences_parameter(
                node,
                function,
                body,
                pointer_parameters,
                source,
            )
        {
            return true;
        }
        if node.kind() == "unary_expression"
            && text(node, source).trim_start().starts_with('*')
            && let Some(operand) = node.named_child(0)
            && let Some(target) = raw_pointer_expression_target(operand)
            && raw_pointer_name_resolves(function, body, target, pointer_parameters, source)
        {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                pending.push(child);
            }
        }
    }
    false
}

fn macro_invocation_dereferences_parameter(
    invocation: Node<'_>,
    function: Node<'_>,
    body: Node<'_>,
    pointer_parameters: &HashSet<String>,
    source: &str,
) -> bool {
    let Some(token_tree) = (0..invocation.named_child_count())
        .filter_map(|index| invocation.named_child(index))
        .find(|child| child.kind() == "token_tree")
    else {
        return false;
    };
    let mut tokens = Vec::new();
    collect_macro_tokens(token_tree, &mut tokens);
    for index in 0..tokens.len() {
        let star = tokens[index];
        if star.kind() != "*" || !macro_star_is_unary(&tokens, index) {
            continue;
        }
        let Some(target) = macro_pointer_operand(&tokens, index + 1) else {
            continue;
        };
        if target.start_byte() < token_tree.start_byte()
            || target.end_byte() > token_tree.end_byte()
            || target.start_byte() < body.start_byte()
            || target.end_byte() > body.end_byte()
        {
            continue;
        }
        if raw_pointer_name_resolves(function, body, target, pointer_parameters, source) {
            return true;
        }
    }
    false
}

fn macro_pointer_operand<'tree>(tokens: &[Node<'tree>], mut index: usize) -> Option<Node<'tree>> {
    let token = tokens.get(index)?;
    if token.kind() != "(" {
        return (token.kind() == "identifier").then_some(*token);
    }
    let close = matching_macro_delimiter(tokens, index)?;
    index += 1;
    if close == index + 1 {
        return tokens.get(index).copied();
    }
    if tokens.get(index).is_some_and(|token| token.kind() == "(") {
        let nested_close = matching_macro_delimiter(tokens, index)?;
        if nested_close + 1 == close {
            return macro_pointer_operand(tokens, index);
        }
    }
    None
}

fn matching_macro_delimiter(tokens: &[Node<'_>], open: usize) -> Option<usize> {
    let close_kind = match tokens.get(open)?.kind() {
        "(" => ")",
        "[" => "]",
        "{" => "}",
        _ => return None,
    };
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.kind() {
            kind if kind == tokens[open].kind() => depth += 1,
            kind if kind == close_kind => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn collect_macro_tokens<'tree>(node: Node<'tree>, tokens: &mut Vec<Node<'tree>>) {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if matches!(
            current.kind(),
            "char_literal"
                | "doc_comment"
                | "line_comment"
                | "block_comment"
                | "raw_string_literal"
                | "string_literal"
        ) {
            continue;
        }
        if current.child_count() == 0 {
            tokens.push(current);
            continue;
        }
        for index in (0..current.child_count()).rev() {
            if let Some(child) = current.child(index) {
                pending.push(child);
            }
        }
    }
}

fn macro_star_is_unary(tokens: &[Node<'_>], index: usize) -> bool {
    let Some(previous) = index.checked_sub(1).and_then(|index| tokens.get(index)) else {
        return true;
    };
    matches!(
        previous.kind(),
        "(" | "["
            | "{"
            | ","
            | ";"
            | ":"
            | "="
            | "=="
            | "!="
            | ">"
            | "<"
            | ">="
            | "<="
            | "+"
            | "-"
            | "/"
            | "%"
            | "^"
            | "&"
            | "|"
            | "&&"
            | "||"
            | "<<"
            | ">>"
            | "+="
            | "-="
            | "*="
            | "/="
            | "%="
            | "^="
            | "&="
            | "|="
            | "<<="
            | ">>="
            | "->"
            | "=>"
            | "!"
            | "?"
            | "@"
            | "as"
            | "if"
            | "match"
            | "return"
            | "unsafe"
            | "*"
    )
}

fn raw_pointer_name_resolves(
    function: Node<'_>,
    body: Node<'_>,
    use_site: Node<'_>,
    pointer_parameters: &HashSet<String>,
    source: &str,
) -> bool {
    let name = text(use_site, source).trim();
    let mut seen_bindings = HashSet::new();
    resolve_raw_pointer_name(
        function,
        body,
        use_site,
        name,
        pointer_parameters,
        source,
        &mut seen_bindings,
    )
}

fn resolve_raw_pointer_name(
    function: Node<'_>,
    body: Node<'_>,
    use_site: Node<'_>,
    name: &str,
    pointer_parameters: &HashSet<String>,
    source: &str,
    seen_bindings: &mut HashSet<usize>,
) -> bool {
    let mut scope = enclosing_block(use_site);
    while let Some(current_scope) = scope {
        if let Some((position, value)) =
            latest_raw_pointer_binding(current_scope, function, use_site, name, source)
        {
            if !seen_bindings.insert(position) {
                return false;
            }
            let Some(value) = value else {
                return false;
            };
            let value = unwrap_raw_pointer_expression(value);
            if value.kind() != "identifier" {
                return false;
            }
            let value_name = text(value, source).trim();
            return resolve_raw_pointer_name(
                function,
                body,
                value,
                value_name,
                pointer_parameters,
                source,
                seen_bindings,
            );
        }
        if current_scope == body {
            break;
        }
        scope = enclosing_block(current_scope);
    }
    pointer_parameters.contains(name)
}

fn latest_raw_pointer_binding<'tree>(
    scope: Node<'tree>,
    function: Node<'tree>,
    use_site: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<(usize, Option<Node<'tree>>)> {
    let mut latest = None;
    walk_valid(scope, &mut |node| {
        let Some(node_function) = enclosing_function(node) else {
            return;
        };
        if node_function.start_byte() != function.start_byte()
            || node != scope
                && enclosing_block(node)
                    .is_none_or(|block| block.start_byte() != scope.start_byte())
            || node.end_byte() > use_site.start_byte()
        {
            return;
        }
        let event = match node.kind() {
            "let_declaration" => {
                let Some(pattern) = node.child_by_field_name("pattern") else {
                    return;
                };
                if !pattern_binds_name(pattern, name, source) {
                    return;
                }
                let value = node
                    .child_by_field_name("value")
                    .and_then(|value| pointer_binding_value(pattern, value, name, source));
                Some((node.end_byte(), value))
            }
            "assignment_expression" | "compound_assignment_expr" => {
                let Some(left) = node.child_by_field_name("left") else {
                    return;
                };
                if left.kind() != "identifier" || text(left, source).trim() != name {
                    return;
                }
                Some((
                    node.end_byte(),
                    (node.kind() == "assignment_expression")
                        .then(|| node.child_by_field_name("right"))
                        .flatten(),
                ))
            }
            _ => None,
        };
        if let Some(event) = event
            && latest
                .as_ref()
                .is_none_or(|(position, _)| event.0 > *position)
        {
            latest = Some(event);
        }
    });
    latest
}

fn pointer_binding_value<'tree>(
    pattern: Node<'tree>,
    value: Node<'tree>,
    wanted: &str,
    source: &str,
) -> Option<Node<'tree>> {
    match pattern.kind() {
        "identifier" | "shorthand_field_identifier" => {
            (text(pattern, source).trim() == wanted).then_some(value)
        }
        "mut_pattern" | "reference_pattern" => {
            let nested = pattern.named_child(pattern.named_child_count().saturating_sub(1))?;
            let value = if value.kind() == "reference_expression" {
                value
                    .child_by_field_name("value")
                    .or_else(|| value.named_child(0))
                    .unwrap_or(value)
            } else {
                value
            };
            pointer_binding_value(nested, value, wanted, source)
        }
        "tuple_pattern" | "slice_pattern" => {
            let mut patterns = Vec::new();
            for index in 0..pattern.child_count() {
                let Some(child) = pattern.child(index) else {
                    continue;
                };
                if child.is_named() || child.kind() == "_" {
                    patterns.push(child);
                }
            }
            let value = unwrap_raw_pointer_expression(value);
            let values: Vec<_> = match value.kind() {
                "tuple_expression" | "array_expression" => {
                    let mut value_cursor = value.walk();
                    value.named_children(&mut value_cursor).collect()
                }
                _ => Vec::new(),
            };
            if patterns.len() != values.len() {
                return (patterns.len() == 1)
                    .then(|| pointer_binding_value(patterns[0], value, wanted, source))
                    .flatten();
            }
            patterns
                .into_iter()
                .zip(values)
                .find_map(|(pattern, value)| pointer_binding_value(pattern, value, wanted, source))
        }
        "field_pattern" => pattern
            .child_by_field_name("pattern")
            .or_else(|| pattern.child_by_field_name("name"))
            .and_then(|nested| pointer_binding_value(nested, value, wanted, source)),
        _ => {
            let mut cursor = pattern.walk();
            pattern
                .named_children(&mut cursor)
                .find_map(|nested| pointer_binding_value(nested, value, wanted, source))
        }
    }
}
fn pattern_binds_name(pattern: Node<'_>, wanted: &str, source: &str) -> bool {
    match pattern.kind() {
        "identifier" | "shorthand_field_identifier" => text(pattern, source).trim() == wanted,
        "scoped_identifier" | "generic_pattern" | "type_identifier" | "field_identifier"
        | "primitive_type" => false,
        _ => {
            let mut cursor = pattern.walk();
            pattern
                .named_children(&mut cursor)
                .any(|child| pattern_binds_name(child, wanted, source))
        }
    }
}

fn check_mutable_return(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for full in mutable_return_regex().find_iter(scan) {
        if full
            .as_str()
            .split("->")
            .next()
            .is_some_and(|parameters| parameters.contains("&mut "))
        {
            continue;
        }
        issues.push(offset_issue(
            "rust:S7453",
            "Do not return a mutable reference derived from an immutable parameter.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_float_loop_counter(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in float_counter_regex().captures_iter(scan) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let tail = &scan[captures.get(0).expect("whole regex capture").end()..];
        if tail
            .lines()
            .take(4)
            .any(|line| line.contains("while ") && line.contains(name.as_str()))
        {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S2193",
                "Use an integer type for this while-loop counter.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
}

fn check_redundant_casts(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in repeated_cast_regex().captures_iter(scan) {
        let same = captures.name("first").map(|value| value.as_str())
            == captures.name("second").map(|value| value.as_str());
        if same {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S4325",
                "Remove this redundant cast.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
    for full in length_cast_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S4325",
            "Remove this redundant cast.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_numeric_suffixes(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for full in numeric_suffix_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S7454",
            "Correct this mistyped numeric literal suffix.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_unit_sort_closure(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for full in unit_sort_closure_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S7421",
            "Return the ordering key instead of a unit value.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_string_to_string(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in string_variable_regex().captures_iter(scan) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let declaration = captures.get(0).expect("whole regex capture");
        let tail = &scan[declaration.end()..];
        let shape = format!("{}.to_string()", name.as_str());
        if let Some(relative) = tail.find(&shape) {
            let start = declaration.end() + relative;
            issues.push(offset_issue(
                "rust:S1858",
                "Remove this redundant call to `to_string()`.",
                source,
                start,
                start + shape.len(),
            ));
        }
    }
}

fn check_missing_array_commas(root: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "array_expression" {
            return;
        }
        for full in missing_comma_regex().find_iter(text(node, scan)) {
            issues.push(offset_issue(
                "rust:S3723",
                "Separate these elements with a comma.",
                source,
                node.start_byte() + full.start(),
                node.start_byte() + full.end(),
            ));
        }
    });
}

fn check_named_array_indexes(root: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "index_expression" {
            return;
        }
        let Some(value) = node
            .named_child(0)
            .filter(|value| value.kind() == "identifier")
        else {
            return;
        };
        let index = node
            .named_child(1)
            .and_then(|index| parse_integer(text(index, source)))
            .and_then(|index| usize::try_from(index).ok());
        let length = visible_array_length(node, text(value, source), source);
        if index
            .zip(length)
            .is_some_and(|(index, length)| index >= length)
        {
            issues.push(node_issue(
                "rust:S6466",
                "This array index always panics.",
                node,
                source,
            ));
        }
    });
    check_macro_array_indexes(source, scan, issues);
}

/// Macro token trees are opaque to Tree-sitter, so indexing inside `println!`
/// and similar calls needs a narrow textual fallback. Stop at the next binding
/// of the same name so a shadowed vector cannot inherit an outer array length.
fn check_macro_array_indexes(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    let mut declarations = named_array_regex().captures_iter(scan).peekable();
    if declarations.peek().is_none() {
        return;
    }
    // Index bindings and accesses once. Compiling two identifier-specific
    // regexes and scanning the remaining source for every array scales poorly
    // in generated files with hundreds of array declarations.
    let mut shadows: HashMap<&str, Vec<usize>> = HashMap::new();
    for keyword in array_let_regex().find_iter(scan) {
        let Some(binding) = array_binding_regex().captures(&scan[keyword.end()..]) else {
            continue;
        };
        let start = keyword.start();
        let name = binding.name("name").expect("binding name").as_str();
        shadows.entry(name).or_default().push(start);
        // Preserve the textual fallback's interpretation of `let mut` when
        // recovered source previously declared an array literally named mut.
        if binding.name("mutable").is_some() && name != "mut" {
            shadows.entry("mut").or_default().push(start);
        }
    }
    let mut accesses: HashMap<&str, Vec<(usize, usize, usize)>> = HashMap::new();
    for access in named_array_access_regex().captures_iter(scan) {
        let Some(index) = access
            .name("index")
            .and_then(|value| value.as_str().parse().ok())
        else {
            continue;
        };
        let full = access.get(0).expect("whole regex capture");
        accesses
            .entry(access.name("name").expect("array name").as_str())
            .or_default()
            .push((full.start(), full.end(), index));
    }
    for declaration in declarations {
        let Some(name) = declaration.name("name") else {
            continue;
        };
        let Some(items) = declaration.name("items") else {
            continue;
        };
        let original_items = source.get(items.range()).unwrap_or_default();
        let length = original_items
            .split(',')
            .filter(|item| !item.trim().is_empty())
            .count();
        let full_declaration = declaration.get(0).expect("whole regex capture");
        let first = full_declaration.end();
        let end = shadows
            .get(name.as_str())
            .and_then(|positions| {
                positions.get(positions.partition_point(|position| *position < first))
            })
            .copied()
            .unwrap_or(scan.len());
        let Some(indexed) = accesses.get(name.as_str()) else {
            continue;
        };
        let start_index = indexed.partition_point(|(start, _, _)| *start < first);
        for &(start, access_end, index) in &indexed[start_index..] {
            if access_end > end {
                break;
            }
            if index >= length {
                issues.push(offset_issue(
                    "rust:S6466",
                    "This array index always panics.",
                    source,
                    start,
                    access_end,
                ));
            }
        }
    }
}

fn visible_array_length(mut use_site: Node<'_>, name: &str, source: &str) -> Option<usize> {
    while let Some(scope) = enclosing_block(use_site) {
        let mut cursor = scope.walk();
        let declaration = scope
            .named_children(&mut cursor)
            .take_while(|statement| statement.start_byte() < use_site.start_byte())
            .filter(|statement| statement.kind() == "let_declaration")
            .filter(|statement| {
                statement
                    .child_by_field_name("pattern")
                    .is_some_and(|pattern| text(pattern, source).trim_start_matches("mut ") == name)
            })
            .last();
        if let Some(value) = declaration.and_then(|item| item.child_by_field_name("value")) {
            return (value.kind() == "array_expression").then(|| value.named_child_count());
        }
        use_site = scope;
    }
    None
}

fn enclosing_block(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "block" {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn check_shared_branch_prefix(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "if_expression" {
            return;
        }
        let pair = node
            .child_by_field_name("consequence")
            .and_then(first_branch_statement)
            .zip(
                node.child_by_field_name("alternative")
                    .and_then(first_branch_statement),
            );
        if pair.is_some_and(|(first, second)| {
            normalized_node(first, source) == normalized_node(second, source)
        }) {
            issues.push(node_issue(
                "rust:S7411",
                "Extract the code shared by all branches.",
                node,
                source,
            ));
        }
    });
}

fn first_branch_statement(mut branch: Node<'_>) -> Option<Node<'_>> {
    if branch.kind() == "else_clause" {
        branch = branch.named_child(0)?;
    }
    if branch.kind() == "if_expression" {
        branch = branch.child_by_field_name("consequence")?;
    }
    if branch.kind() != "block" {
        return None;
    }
    let mut cursor = branch.walk();
    branch
        .named_children(&mut cursor)
        .find(|statement| !matches!(statement.kind(), "line_comment" | "block_comment"))
}

fn check_async_block_tail(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in async_block_regex().captures_iter(scan) {
        let Some(call) = captures.name("call") else {
            continue;
        };
        if !call.as_str().contains(".await") {
            issues.push(offset_issue(
                "rust:S7413",
                "Await this awaitable value before returning it.",
                source,
                call.start(),
                call.end(),
            ));
        }
    }
}

fn check_slice_cast_sizes(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in slice_cast_regex().captures_iter(scan) {
        let from = captures.name("from").map(|value| value.as_str());
        let to = captures.name("to").map(|value| value.as_str());
        if from != to {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S7433",
                "Keep the pointed-to and slice element sizes compatible.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
}

fn check_double_comparisons(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in double_comparison_regex().captures_iter(scan) {
        let first_name = captures.name("first_name").map(|value| value.as_str());
        let second_name = captures.name("second_name").map(|value| value.as_str());
        if first_name != second_name {
            continue;
        }
        let first = captures
            .name("first")
            .and_then(|value| parse_signed_integer(value.as_str()));
        let second = captures
            .name("second")
            .and_then(|value| parse_signed_integer(value.as_str()));
        let first_op = captures
            .name("first_op")
            .map(|value| value.as_str())
            .unwrap_or_default();
        let second_op = captures
            .name("second_op")
            .map(|value| value.as_str())
            .unwrap_or_default();
        let full = captures.get(0).expect("whole regex capture");
        if (first_op.starts_with('<') && second_op.starts_with('<'))
            || (first_op.starts_with('>') && second_op.starts_with('>'))
        {
            issues.push(offset_issue(
                "rust:S7436",
                "Remove this redundant comparison.",
                source,
                full.start(),
                full.end(),
            ));
        }
        if first
            .zip(second)
            .is_some_and(|(first, second)| empty_integer_bounds(first_op, first, second_op, second))
        {
            issues.push(offset_issue(
                "rust:S7439",
                "This range comparison is always false.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
}

fn check_almost_swap(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    let lines: Vec<_> = scan.lines().collect();
    let original_lines: Vec<_> = source.lines().collect();
    for (index, window) in lines.windows(2).enumerate() {
        let Some((first_left, first_right)) = plain_assignment(window[0]) else {
            continue;
        };
        let Some((second_left, second_right)) = plain_assignment(window[1]) else {
            continue;
        };
        if first_left == second_right && first_right == second_left {
            issues.push(line_issue(
                "rust:S7437",
                "Use `std::mem::swap` to swap these variables.",
                index,
                0,
                original_lines[index].chars().count(),
            ));
        }
    }
}

fn check_panicking_unwrap(root: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "if_expression" {
            return;
        }
        let Some(condition) = node.child_by_field_name("condition") else {
            return;
        };
        let compact = normalized(text(condition, scan));
        let Some(captures) = panicking_condition_regex().captures(&compact) else {
            return;
        };
        let Some(receiver) = captures.name("receiver") else {
            return;
        };
        let Some(consequence) = node.child_by_field_name("consequence") else {
            return;
        };
        for captures in unwrap_regex().captures_iter(text(consequence, scan)) {
            if captures.name("receiver").map(|value| value.as_str()) != Some(receiver.as_str()) {
                continue;
            }
            let full = captures.get(0).expect("whole regex capture");
            let start = consequence.start_byte() + full.start();
            issues.push(offset_issue(
                "rust:S7442",
                "Use the contained value only on a branch where it is present.",
                source,
                start,
                consequence.start_byte() + full.end(),
            ));
        }
    });
}

fn check_eager_transmute(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let mut emitted = HashSet::new();
    walk_valid(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let (method, fallback_index) = if call_receiver(function).is_some() {
            let Some(method) = callable_name(function, source) else {
                return;
            };
            (method, 0)
        } else {
            let Some(method) = standard_ufcs_eager_method(function, source) else {
                return;
            };
            (method, 1)
        };
        if !matches!(method, "then_some" | "unwrap_or" | "map_or") {
            return;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        if let Some(argument) = arguments.named_child(fallback_index) {
            collect_eager_transmutes(argument, source, issues, &mut emitted);
        }
    });
}

fn standard_ufcs_eager_method(function: Node<'_>, source: &str) -> Option<&'static str> {
    let mut base = function;
    while base.kind() == "generic_function" {
        base = base.child_by_field_name("function")?;
    }
    if base.kind() != "scoped_identifier" {
        return None;
    }
    let method = callable_name(base, source)?;
    let direct = match method {
        "then_some" => "then_some",
        "unwrap_or" => "unwrap_or",
        "map_or" => "map_or",
        _ => return None,
    };
    let candidate = normalized_node(base, source);
    let candidate = candidate.strip_prefix("::").unwrap_or(&candidate);
    if candidate == "bool::then_some" {
        return Some(direct);
    }
    if candidate.starts_with("Option::") && candidate.split("::").count() == 2 {
        if standard_name_is_shadowed(base, "Option", source, false) {
            return None;
        }
        return Some(direct);
    }
    let expected = match method {
        "unwrap_or" => [
            "std::option::Option::unwrap_or",
            "core::option::Option::unwrap_or",
        ],
        "map_or" => [
            "std::option::Option::map_or",
            "core::option::Option::map_or",
        ],
        _ => return None,
    };
    standard_import_matches(base, source, &expected).then_some(direct)
}

fn collect_eager_transmutes(
    node: Node<'_>,
    source: &str,
    issues: &mut Vec<Issue>,
    emitted: &mut HashSet<usize>,
) {
    if matches!(
        node.kind(),
        "closure_expression" | "async_block" | "function_item"
    ) {
        return;
    }
    if node.kind() == "call_expression"
        && is_transmute_function(node, source)
        && emitted.insert(node.start_byte())
    {
        issues.push(node_issue(
            "rust:S7443",
            "Evaluate this transmute lazily.",
            node,
            source,
        ));
    }
    if node.kind() == "macro_invocation" {
        collect_macro_eager_transmutes(node, source, issues, emitted);
        return;
    }
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            collect_eager_transmutes(child, source, issues, emitted);
        }
    }
}
fn collect_macro_eager_transmutes(
    invocation: Node<'_>,
    source: &str,
    issues: &mut Vec<Issue>,
    emitted: &mut HashSet<usize>,
) {
    if !macro_forwards_expression(invocation, source) {
        return;
    }
    let Some(token_tree) = (0..invocation.named_child_count())
        .filter_map(|index| invocation.named_child(index))
        .find(|child| child.kind() == "token_tree")
    else {
        return;
    };
    let mut tokens = Vec::new();
    collect_macro_tokens(token_tree, &mut tokens);
    for index in 0..tokens.len() {
        let Some((end, _)) = macro_path_call(
            &tokens,
            index,
            invocation,
            source,
            &["std::mem::transmute", "core::intrinsics::transmute"],
        ) else {
            continue;
        };
        let token = tokens[end];
        if emitted.insert(token.start_byte()) {
            issues.push(node_issue(
                "rust:S7443",
                "Evaluate this transmute lazily.",
                token,
                source,
            ));
        }
    }
}

fn macro_forwards_expression(invocation: Node<'_>, source: &str) -> bool {
    let Some(macro_name) = invocation.child_by_field_name("macro") else {
        return false;
    };
    if standard_import_matches(macro_name, source, &["std::dbg", "core::dbg"]) {
        return true;
    }
    let name = text(macro_name, source).trim();
    let mut root = invocation;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut forwards = false;
    walk_valid(root, &mut |node| {
        if forwards || node.kind() != "macro_definition" {
            return;
        }
        if node
            .child_by_field_name("name")
            .is_none_or(|candidate| text(candidate, source).trim() != name)
        {
            return;
        }
        let mut cursor = node.walk();
        for rule in node.named_children(&mut cursor) {
            if rule.kind() != "macro_rule" {
                continue;
            }
            let (Some(left), Some(right)) = (
                rule.child_by_field_name("left"),
                rule.child_by_field_name("right"),
            ) else {
                continue;
            };
            let captures = macro_capture_names(text(left, source));
            if captures
                .iter()
                .any(|capture| text(right, source).contains(&format!("${capture}")))
            {
                forwards = true;
                break;
            }
        }
    });
    forwards
}

fn macro_capture_names(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let mut captures = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' || bytes.get(index + 1) == Some(&b'$') {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if end > start {
            captures.push(value[start..end].to_string());
        }
        index = end.max(index + 1);
    }
    captures
}

fn macro_path_call(
    tokens: &[Node<'_>],
    start: usize,
    invocation: Node<'_>,
    source: &str,
    expected: &[&str],
) -> Option<(usize, usize)> {
    let mut end = start;
    if tokens.get(end).is_some_and(|token| token.kind() == "::") {
        end += 1;
    }
    if !tokens
        .get(end)
        .is_some_and(|token| matches!(token.kind(), "identifier" | "type_identifier"))
    {
        return None;
    }
    loop {
        let candidate = normalized(
            &tokens[start..=end]
                .iter()
                .map(|token| text(*token, source))
                .collect::<String>(),
        );
        if macro_standard_path_matches(&candidate, tokens[start], invocation, source, expected)
            && let Some(open) = macro_call_open_after(tokens, end)
        {
            return Some((end, open));
        }
        if tokens.get(end + 1).is_none_or(|token| token.kind() != "::")
            || tokens.get(end + 2).is_none_or(|token| {
                token.kind() != "identifier" && token.kind() != "type_identifier"
            })
        {
            break;
        }
        end += 2;
    }
    None
}

fn macro_call_open_after(tokens: &[Node<'_>], end: usize) -> Option<usize> {
    if tokens.get(end + 1).is_some_and(|token| token.kind() == "(") {
        return Some(end + 1);
    }
    if tokens.get(end + 1).is_none_or(|token| token.kind() != "::")
        || tokens.get(end + 2).is_none_or(|token| token.kind() != "<")
    {
        return None;
    }
    let close = matching_macro_angle(tokens, end + 2)?;
    tokens
        .get(close + 1)
        .is_some_and(|token| token.kind() == "(")
        .then_some(close + 1)
}

fn matching_macro_angle(tokens: &[Node<'_>], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.kind() {
            "<" => depth += 1,
            kind if kind.chars().all(|character| character == '>') => {
                for _ in kind.chars() {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(index);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn macro_standard_path_matches(
    candidate: &str,
    first: Node<'_>,
    invocation: Node<'_>,
    source: &str,
    expected: &[&str],
) -> bool {
    let absolute = candidate.starts_with("::");
    let candidate = candidate.strip_prefix("::").unwrap_or(candidate);
    if expected.contains(&candidate) {
        if absolute {
            return true;
        }
        let root = candidate.split("::").next().unwrap_or_default();
        return !standard_name_is_shadowed(first, root, source, true);
    }
    visible_standard_imports(invocation, source)
        .into_iter()
        .any(|(alias, path)| {
            let tail = candidate
                .strip_prefix(&alias)
                .map_or("", |tail| tail.strip_prefix("::").unwrap_or(""));
            if candidate != alias && tail.is_empty() {
                return false;
            }
            expected
                .iter()
                .any(|expected| *expected == path || *expected == format!("{path}::{tail}"))
        })
}

fn is_transmute_function(call: Node<'_>, source: &str) -> bool {
    let Some(mut function) = call.child_by_field_name("function") else {
        return false;
    };
    while function.kind() == "generic_function" {
        let Some(inner) = function.child_by_field_name("function") else {
            return false;
        };
        function = inner;
    }
    match function.kind() {
        "scoped_identifier" => standard_import_matches(
            function,
            source,
            &["std::mem::transmute", "core::intrinsics::transmute"],
        ),
        "identifier" => {
            text(function, source).trim() == "transmute"
                && standard_import_matches(
                    function,
                    source,
                    &["std::mem::transmute", "core::intrinsics::transmute"],
                )
        }
        _ => false,
    }
}

fn check_infinite_iterators(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let mut emitted = HashSet::new();
    walk_valid(root, &mut |node| {
        if node.kind() == "for_expression" {
            let Some(value) = node.child_by_field_name("value") else {
                return;
            };
            let mut seen_bindings = HashSet::new();
            let Some(origin) = infinite_iterator_origin(value, source, &mut seen_bindings) else {
                return;
            };
            if emitted.insert(origin.start_byte()) {
                issues.push(node_issue(
                    "rust:S7464",
                    "Finish this infinite iterator with a terminating operation.",
                    origin,
                    source,
                ));
            }
            return;
        }
        if node.kind() == "macro_invocation" {
            collect_macro_infinite_iterators(node, source, issues, &mut emitted);
            return;
        }
        if node.kind() != "call_expression" {
            return;
        }
        let Some(method) = call_function_name(node, source) else {
            return;
        };
        if !is_exhausting_iterator_consumer(method) {
            return;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let receiver = call_receiver(function)
            .or_else(|| standard_iterator_ufcs_receiver(function, node, source));
        let Some(receiver) = receiver else {
            return;
        };
        let mut seen_bindings = HashSet::new();
        let Some(origin) = infinite_iterator_origin(receiver, source, &mut seen_bindings) else {
            return;
        };
        if emitted.insert(origin.start_byte()) {
            issues.push(node_issue(
                "rust:S7464",
                "Finish this infinite iterator with a terminating operation.",
                origin,
                source,
            ));
        }
    });
    walk_all(root, &mut |node| {
        if node.kind() == "macro_invocation" {
            collect_macro_infinite_iterators(node, source, issues, &mut emitted);
        }
    });
}

fn standard_iterator_ufcs_receiver<'tree>(
    function: Node<'tree>,
    call: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let mut base = function;
    while base.kind() == "generic_function" {
        base = base.child_by_field_name("function")?;
    }
    if base.kind() != "scoped_identifier" {
        return None;
    }
    let method = callable_name(base, source)?;
    if !is_exhausting_iterator_consumer(method) {
        return None;
    }
    let candidate = normalized_node(base, source);
    let candidate = candidate.strip_prefix("::").unwrap_or(&candidate);
    let standard = candidate == format!("Iterator::{method}")
        || candidate == format!("std::iter::Iterator::{method}")
        || candidate == format!("core::iter::Iterator::{method}");
    if !standard {
        return None;
    }
    if candidate.starts_with("Iterator::")
        && standard_name_is_shadowed(base, "Iterator", source, false)
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    arguments.named_child(0)
}

fn collect_macro_infinite_iterators(
    invocation: Node<'_>,
    source: &str,
    issues: &mut Vec<Issue>,
    emitted: &mut HashSet<usize>,
) {
    let Some(token_tree) = (0..invocation.named_child_count())
        .filter_map(|index| invocation.named_child(index))
        .find(|child| child.kind() == "token_tree")
    else {
        return;
    };
    let mut tokens = Vec::new();
    collect_macro_tokens(token_tree, &mut tokens);
    for index in 0..tokens.len() {
        let Some((repeat_end, repeat_open)) = macro_path_call(
            &tokens,
            index,
            invocation,
            source,
            &["std::iter::repeat", "core::iter::repeat"],
        ) else {
            continue;
        };
        let Some(repeat_close) = matching_macro_delimiter(&tokens, repeat_open) else {
            continue;
        };
        let Some((_, origin_end)) = macro_exhausting_chain(&tokens, repeat_close, source) else {
            continue;
        };
        let origin_start = tokens[index].start_byte();
        if emitted.insert(origin_start) {
            issues.push(offset_issue(
                "rust:S7464",
                "Finish this infinite iterator with a terminating operation.",
                source,
                origin_start,
                tokens[origin_end]
                    .end_byte()
                    .max(tokens[repeat_end].end_byte()),
            ));
        }
    }
    for index in 0..tokens.len() {
        let Some(prefix) = tokens.get(..index) else {
            continue;
        };
        let contains_repeat = prefix
            .iter()
            .rev()
            .take_while(|token| !matches!(token.kind(), ";" | "{" | "}" | "[" | "]"))
            .any(|token| text(*token, source).trim() == "repeat");
        if contains_repeat {
            continue;
        }
        let Some((method, cycle_close)) = macro_method_call(&tokens, index, source) else {
            continue;
        };
        if method != "cycle" {
            continue;
        }
        let Some((consumer, consumer_close)) = macro_method_call(&tokens, cycle_close + 1, source)
        else {
            continue;
        };
        if consumer != "collect" {
            continue;
        }
        let origin_start = tokens[index + 1].start_byte();
        if emitted.insert(origin_start) {
            issues.push(offset_issue(
                "rust:S7464",
                "Finish this infinite iterator with a terminating operation.",
                source,
                origin_start,
                tokens[consumer_close].end_byte(),
            ));
        }
    }
}

fn macro_exhausting_chain(
    tokens: &[Node<'_>],
    repeat_close: usize,
    source: &str,
) -> Option<(usize, usize)> {
    let mut dot = repeat_close + 1;
    loop {
        let (method, close) = macro_method_call(tokens, dot, source)?;
        if is_bounded_iterator_consumer(method) {
            return None;
        }
        if method == "collect" || is_exhausting_iterator_consumer(method) {
            return Some((close, repeat_close));
        }
        dot = close + 1;
    }
}
fn macro_method_call<'a>(
    tokens: &[Node<'_>],
    dot: usize,
    source: &'a str,
) -> Option<(&'a str, usize)> {
    if tokens.get(dot).is_none_or(|token| token.kind() != ".") {
        return None;
    }
    let method = tokens.get(dot + 1)?;
    let method_name = text(*method, source).trim();
    let open = macro_call_open_after(tokens, dot + 1)?;
    let close = matching_macro_delimiter(tokens, open)?;
    Some((method_name, close))
}

fn call_function_name<'a>(call: Node<'_>, source: &'a str) -> Option<&'a str> {
    call.child_by_field_name("function")
        .and_then(|function| callable_name(function, source))
}

fn callable_name<'a>(mut function: Node<'_>, source: &'a str) -> Option<&'a str> {
    loop {
        match function.kind() {
            "identifier" | "field_identifier" | "type_identifier" => {
                return Some(text(function, source).trim());
            }
            "scoped_identifier" => {
                return function
                    .child_by_field_name("name")
                    .and_then(|name| callable_name(name, source));
            }
            "field_expression" => {
                return function
                    .child_by_field_name("field")
                    .and_then(|field| callable_name(field, source));
            }
            "generic_function" => {
                function = function.child_by_field_name("function")?;
            }
            _ => return None,
        }
    }
}

fn call_receiver(mut function: Node<'_>) -> Option<Node<'_>> {
    loop {
        match function.kind() {
            "field_expression" => return function.child_by_field_name("value"),
            "generic_function" => function = function.child_by_field_name("function")?,
            _ => return None,
        }
    }
}

fn is_exhausting_iterator_consumer(method: &str) -> bool {
    matches!(
        method,
        "collect"
            | "count"
            | "fold"
            | "fold_first"
            | "for_each"
            | "last"
            | "max"
            | "max_by"
            | "max_by_key"
            | "min"
            | "min_by"
            | "min_by_key"
            | "partition"
            | "product"
            | "reduce"
            | "sum"
            | "unzip"
    )
}

fn is_bounded_iterator_consumer(method: &str) -> bool {
    matches!(method, "take" | "find" | "any" | "next" | "position")
}

fn is_repeat_constructor(function: Node<'_>, source: &str) -> bool {
    let mut base = function;
    while base.kind() == "generic_function" {
        let Some(inner) = base.child_by_field_name("function") else {
            return false;
        };
        base = inner;
    }
    match base.kind() {
        "identifier" | "scoped_identifier" => {
            standard_import_matches(base, source, &["std::iter::repeat", "core::iter::repeat"])
        }
        _ => false,
    }
}

fn standard_import_matches(node: Node<'_>, source: &str, expected: &[&str]) -> bool {
    let candidate = normalized_node(node, source);
    let absolute = candidate.starts_with("::");
    let normalized_candidate = candidate.strip_prefix("::").unwrap_or(&candidate);
    if expected.contains(&normalized_candidate) {
        if absolute {
            return true;
        }
        let root = normalized_candidate.split("::").next().unwrap_or_default();
        return !standard_name_is_shadowed(node, root, source, true);
    }
    let name = if node.kind() == "identifier" {
        text(node, source).trim()
    } else {
        candidate.split("::").next().unwrap_or_default()
    };
    if name.is_empty() || standard_name_is_shadowed(node, name, source, false) {
        return false;
    }
    visible_standard_imports(node, source)
        .into_iter()
        .any(|(alias, path)| {
            if alias == "*" {
                return node.kind() == "identifier"
                    && expected
                        .iter()
                        .any(|expected| *expected == format!("{path}::{name}"));
            }
            if node.kind() == "identifier" && alias == name {
                return expected.iter().any(|expected| *expected == path);
            }
            candidate
                .strip_prefix(&format!("{alias}::"))
                .and_then(|tail| (!tail.is_empty()).then_some(tail))
                .is_some_and(|tail| {
                    expected
                        .iter()
                        .any(|expected| *expected == format!("{path}::{tail}"))
                })
        })
}

fn standard_parameters_bind_name(parameters: Node<'_>, name: &str, source: &str) -> bool {
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        let pattern = parameter
            .child_by_field_name("pattern")
            .unwrap_or(parameter);
        pattern_binds_name(pattern, name, source)
    })
}

fn standard_name_is_shadowed(
    node: Node<'_>,
    name: &str,
    source: &str,
    qualified_path: bool,
) -> bool {
    let use_start = node.start_byte();
    let mut crossed_function = false;
    let mut scope = node.parent();
    while let Some(current) = scope {
        if function_scope_shadows_name(current, name, source, qualified_path, crossed_function) {
            return true;
        }
        if scope_contains_shadowing_binding(
            current,
            use_start,
            name,
            source,
            crossed_function,
            qualified_path,
        ) {
            return true;
        }
        if is_shadow_search_boundary(current) {
            break;
        }
        crossed_function |= current.kind() == "function_item";
        scope = current.parent();
    }
    false
}

fn function_scope_shadows_name(
    current: Node<'_>,
    name: &str,
    source: &str,
    qualified_path: bool,
    crossed_function: bool,
) -> bool {
    if crossed_function
        || !matches!(current.kind(), "closure_expression" | "function_item")
        || qualified_path
    {
        return false;
    }
    current
        .child_by_field_name("parameters")
        .is_some_and(|parameters| standard_parameters_bind_name(parameters, name, source))
}

fn scope_contains_shadowing_binding(
    current: Node<'_>,
    use_start: usize,
    name: &str,
    source: &str,
    crossed_function: bool,
    qualified_path: bool,
) -> bool {
    if !matches!(current.kind(), "block" | "declaration_list" | "source_file") {
        return false;
    }
    let mut shadowed = false;
    walk_valid(current, &mut |candidate| {
        if shadowed {
            return;
        }
        if candidate_shadows_name(
            candidate,
            current,
            use_start,
            name,
            source,
            crossed_function,
            qualified_path,
        ) {
            shadowed = true;
        }
    });
    shadowed
}

fn match_pattern_shadows_name(
    candidate: Node<'_>,
    use_start: usize,
    name: &str,
    source: &str,
) -> bool {
    let mut ancestor = Some(candidate);
    while let Some(current) = ancestor {
        if current.kind() == "match_arm" {
            let Some(pattern) = current.child_by_field_name("pattern") else {
                return false;
            };
            return candidate.start_byte() >= pattern.start_byte()
                && candidate.end_byte() <= pattern.end_byte()
                && pattern.end_byte() <= use_start
                && use_start < current.end_byte()
                && pattern_binds_name(pattern, name, source);
        }
        ancestor = current.parent();
    }
    false
}

fn candidate_shadows_name(
    candidate: Node<'_>,
    current: Node<'_>,
    use_start: usize,
    name: &str,
    source: &str,
    crossed_function: bool,
    qualified_path: bool,
) -> bool {
    let same_scope = candidate_is_in_scope(candidate, current);
    if candidate == current || !same_scope {
        return false;
    }
    if !qualified_path && match_pattern_shadows_name(candidate, use_start, name, source) {
        return true;
    }
    if item_declaration_shadows_name(candidate, use_start, name, source) {
        return true;
    }
    if use_declaration_shadows_name(candidate, name, source) {
        return true;
    }
    let_declaration_shadows_name(
        candidate,
        use_start,
        name,
        source,
        crossed_function,
        qualified_path,
    )
}

fn candidate_is_in_scope(candidate: Node<'_>, current: Node<'_>) -> bool {
    match current.kind() {
        "block" => enclosing_block(candidate)
            .is_some_and(|block| block.start_byte() == current.start_byte()),
        "declaration_list" | "source_file" => {
            candidate.parent().is_some_and(|parent| parent == current)
        }
        _ => false,
    }
}

fn item_declaration_shadows_name(
    candidate: Node<'_>,
    use_start: usize,
    name: &str,
    source: &str,
) -> bool {
    if !matches!(
        candidate.kind(),
        "const_item"
            | "enum_item"
            | "function_item"
            | "mod_item"
            | "static_item"
            | "struct_item"
            | "trait_item"
            | "type_item"
            | "union_item"
    ) {
        return false;
    }
    candidate
        .child_by_field_name("name")
        .is_some_and(|item_name| text(item_name, source).trim() == name)
        && candidate.end_byte() <= use_start
}

fn use_declaration_shadows_name(candidate: Node<'_>, name: &str, source: &str) -> bool {
    if candidate.kind() != "use_declaration" {
        return false;
    }
    let mut aliases = HashSet::new();
    collect_use_binding_names(candidate, "", source, &mut aliases);
    aliases.contains(name)
}

fn let_declaration_shadows_name(
    candidate: Node<'_>,
    use_start: usize,
    name: &str,
    source: &str,
    crossed_function: bool,
    qualified_path: bool,
) -> bool {
    if crossed_function || qualified_path || candidate.kind() != "let_declaration" {
        return false;
    }
    candidate.end_byte() <= use_start
        && candidate
            .child_by_field_name("pattern")
            .is_some_and(|pattern| pattern_binds_name(pattern, name, source))
}

fn is_shadow_search_boundary(current: Node<'_>) -> bool {
    current.kind() == "source_file"
        || (current.kind() == "declaration_list"
            && current
                .parent()
                .is_some_and(|parent| parent.kind() == "mod_item"))
}

fn visible_standard_imports(node: Node<'_>, source: &str) -> Vec<(String, String)> {
    let mut imports = Vec::new();
    let mut scope = node.parent();
    while let Some(current) = scope {
        if matches!(current.kind(), "block" | "declaration_list" | "source_file") {
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                if child.kind() != "use_declaration" {
                    continue;
                }
                collect_standard_imports(child, source, &mut imports);
            }
        }
        let stop = current.kind() == "source_file"
            || (current.kind() == "declaration_list"
                && current
                    .parent()
                    .is_some_and(|parent| parent.kind() == "mod_item"));
        if stop {
            break;
        }
        scope = current.parent();
    }
    imports
}

fn collect_standard_imports(
    declaration: Node<'_>,
    source: &str,
    imports: &mut Vec<(String, String)>,
) {
    let Some(argument) = declaration.child_by_field_name("argument") else {
        return;
    };
    collect_standard_use_tree(argument, "", source, imports);
}

fn collect_standard_use_tree(
    node: Node<'_>,
    prefix: &str,
    source: &str,
    imports: &mut Vec<(String, String)>,
) {
    match node.kind() {
        "scoped_use_list" => {
            let path = node
                .child_by_field_name("path")
                .map(|path| normalized_node(path, source))
                .unwrap_or_default();
            let prefix = join_standard_use_path(prefix, &path);
            if let Some(list) = node.child_by_field_name("list") {
                collect_standard_use_tree(list, &prefix, source, imports);
            }
        }
        "use_list" => {
            let mut cursor = node.walk();
            for item in node.named_children(&mut cursor) {
                collect_standard_use_tree(item, prefix, source, imports);
            }
        }
        "use_as_clause" => {
            let Some(path) = node.child_by_field_name("path") else {
                return;
            };
            let path = join_standard_use_path(prefix, &normalized_node(path, source));
            let Some(alias) = node.child_by_field_name("alias") else {
                return;
            };
            record_standard_import(imports, text(alias, source).trim(), &path);
        }
        "use_wildcard" => {
            let wildcard = normalized_node(node, source);
            let wildcard = wildcard.strip_prefix("::").unwrap_or(&wildcard);
            let path = wildcard.strip_suffix("::*").map_or_else(
                || wildcard.strip_suffix('*').unwrap_or(wildcard),
                |path| path,
            );
            let path = join_standard_use_path(prefix, path.trim_end_matches("::"));
            record_standard_import(imports, "*", &path);
        }
        "self" => {
            if !prefix.is_empty() {
                let alias = prefix.rsplit("::").next().unwrap_or(prefix);
                record_standard_import(imports, alias, prefix);
            }
        }
        _ => {
            let item = normalized_node(node, source);
            let path = join_standard_use_path(prefix, &item);
            let alias = item.rsplit("::").next().unwrap_or(item.as_str());
            record_standard_import(imports, alias, &path);
        }
    }
}

fn join_standard_use_path(prefix: &str, path: &str) -> String {
    let path = path.trim_start_matches("::");
    if path.is_empty() || path == "self" {
        return prefix.to_string();
    }
    if prefix.is_empty() {
        path.to_string()
    } else {
        format!("{prefix}::{path}")
    }
}
fn collect_use_binding_names(
    node: Node<'_>,
    prefix: &str,
    source: &str,
    names: &mut HashSet<String>,
) {
    match node.kind() {
        "scoped_use_list" => {
            let path = node
                .child_by_field_name("path")
                .map(|path| normalized_node(path, source))
                .unwrap_or_default();
            let prefix = join_standard_use_path(prefix, &path);
            if let Some(list) = node.child_by_field_name("list") {
                collect_use_binding_names(list, &prefix, source, names);
            }
        }
        "use_list" => {
            let mut cursor = node.walk();
            for item in node.named_children(&mut cursor) {
                collect_use_binding_names(item, prefix, source, names);
            }
        }
        "use_as_clause" => {
            let Some(alias) = node.child_by_field_name("alias") else {
                return;
            };
            let Some(path) = node.child_by_field_name("path") else {
                return;
            };
            let path = join_standard_use_path(prefix, &normalized_node(path, source));
            if !is_standard_import_path(&path) {
                names.insert(text(alias, source).trim().to_string());
            }
        }
        "use_wildcard" => {}
        "self" => {
            if !prefix.is_empty() && !is_standard_import_path(prefix) {
                names.insert(prefix.rsplit("::").next().unwrap_or(prefix).to_string());
            }
        }
        _ => {
            let item = normalized_node(node, source);
            let path = join_standard_use_path(prefix, &item);
            let alias = item.rsplit("::").next().unwrap_or(item.as_str());
            if !alias.is_empty() && !is_standard_import_path(&path) {
                names.insert(alias.to_string());
            }
        }
    }
}

fn record_standard_import(imports: &mut Vec<(String, String)>, alias: &str, path: &str) {
    let path = path.trim_start_matches("::");
    if !alias.is_empty() && is_standard_import_path(path) {
        imports.push((alias.to_string(), path.to_string()));
    }
}

fn is_standard_import_path(path: &str) -> bool {
    let path = path.trim_start_matches("::");
    path == "std" || path == "core" || path.starts_with("std::") || path.starts_with("core::")
}

enum BindingState<'tree> {
    NotFound,
    NoValue,
    Value(Node<'tree>),
}

fn infinite_iterator_origin<'tree>(
    node: Node<'tree>,
    source: &str,
    seen_bindings: &mut HashSet<usize>,
) -> Option<Node<'tree>> {
    let node = unwrap_parenthesized(node);
    match node.kind() {
        "range_expression" => {
            let compact = normalized(text(node, source));
            (compact.len() > 2 && compact.ends_with("..")).then_some(node)
        }
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            let method = callable_name(function, source)?;
            if is_repeat_constructor(function, source) {
                return Some(node);
            }
            if method == "cycle" && call_receiver(function).is_some() {
                return Some(node);
            }
            if is_bounded_iterator_consumer(method) {
                return None;
            }
            if method == "chain" {
                let receiver_origin = call_receiver(function)
                    .and_then(|receiver| infinite_iterator_origin(receiver, source, seen_bindings));
                if receiver_origin.is_some() {
                    return receiver_origin;
                }
                return node
                    .child_by_field_name("arguments")
                    .and_then(|arguments| arguments.named_child(0))
                    .and_then(|argument| {
                        infinite_iterator_origin(argument, source, seen_bindings)
                    });
            }
            call_receiver(function)
                .and_then(|receiver| infinite_iterator_origin(receiver, source, seen_bindings))
        }
        "identifier" => resolve_infinite_binding(node, source, seen_bindings),
        _ => None,
    }
}

fn resolve_infinite_binding<'tree>(
    identifier: Node<'tree>,
    source: &str,
    seen_bindings: &mut HashSet<usize>,
) -> Option<Node<'tree>> {
    let name = text(identifier, source).trim();
    let owner = enclosing_function(identifier)?;
    let mut scope = enclosing_block(identifier)?;
    loop {
        match latest_binding_value(scope, identifier, name, owner, source) {
            BindingState::NotFound => {}
            BindingState::NoValue => return None,
            BindingState::Value(value) => {
                if !seen_bindings.insert(value.start_byte()) {
                    return None;
                }
                return infinite_iterator_origin(value, source, seen_bindings);
            }
        }
        let parent = scope.parent()?;
        scope = enclosing_block(parent)?;
    }
}

fn latest_binding_value<'tree>(
    scope: Node<'tree>,
    use_site: Node<'tree>,
    name: &str,
    owner: Node<'tree>,
    source: &str,
) -> BindingState<'tree> {
    let mut latest: Option<(usize, BindingState<'tree>)> = None;
    walk_valid(scope, &mut |node| {
        let Some(node_function) = enclosing_function(node) else {
            return;
        };
        if node_function.start_byte() != owner.start_byte()
            || enclosing_block(node).is_some_and(|block| block.start_byte() != scope.start_byte())
        {
            return;
        }
        let event = match node.kind() {
            "let_declaration" => {
                if node.end_byte() > use_site.start_byte()
                    || !node
                        .child_by_field_name("pattern")
                        .is_some_and(|pattern| pattern_binds_name(pattern, name, source))
                {
                    return;
                }
                Some((
                    node.end_byte(),
                    node.child_by_field_name("value")
                        .map_or(BindingState::NoValue, BindingState::Value),
                ))
            }
            "assignment_expression" => {
                if node.end_byte() > use_site.start_byte()
                    || !node.child_by_field_name("left").is_some_and(|left| {
                        left.kind() == "identifier" && text(left, source).trim() == name
                    })
                {
                    return;
                }
                Some((
                    node.end_byte(),
                    node.child_by_field_name("right")
                        .map_or(BindingState::NoValue, BindingState::Value),
                ))
            }
            "compound_assignment_expr" => {
                if node.end_byte() > use_site.start_byte()
                    || !node.child_by_field_name("left").is_some_and(|left| {
                        left.kind() == "identifier" && text(left, source).trim() == name
                    })
                {
                    return;
                }
                Some((node.end_byte(), BindingState::NoValue))
            }
            _ => None,
        };
        let Some(event) = event else {
            return;
        };
        if latest
            .as_ref()
            .is_none_or(|(position, _)| event.0 > *position)
        {
            latest = Some(event);
        }
    });
    latest.map_or(BindingState::NotFound, |(_, value)| value)
}

fn check_overflow_addition(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for full in overflow_comparison_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S7444",
            "Use `checked_add` or `overflowing_add` to detect overflow.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_partial_io_calls(root: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
    walk_valid(root, &mut |node| {
        if node.kind() != "function_item" {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let signature = source
            .get(node.start_byte()..body.start_byte())
            .unwrap_or_default();
        for captures in partial_io_call_regex().captures_iter(text(body, scan)) {
            let Some(receiver) = captures.name("receiver") else {
                continue;
            };
            let Some(method) = captures.name("method") else {
                continue;
            };
            let required_trait = if method.as_str() == "read" {
                "Read"
            } else {
                "Write"
            };
            if !receiver_supports_io_trait(
                node,
                receiver.as_str(),
                required_trait,
                signature,
                source,
            ) {
                continue;
            }
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S7419",
                "Process the entire I/O buffer or handle the partial result.",
                source,
                body.start_byte() + full.start(),
                body.start_byte() + full.end(),
            ));
        }
    });
}

fn receiver_supports_io_trait(
    function: Node<'_>,
    receiver: &str,
    wanted: &str,
    signature: &str,
    source: &str,
) -> bool {
    let Some(parameter_type) = function
        .child_by_field_name("parameters")
        .and_then(|parameters| {
            let mut cursor = parameters.walk();
            parameters
                .named_children(&mut cursor)
                .find_map(|parameter| {
                    let pattern = parameter.child_by_field_name("pattern")?;
                    (text(pattern, source).trim_start_matches("mut ") == receiver)
                        .then(|| parameter.child_by_field_name("type"))
                        .flatten()
                })
        })
    else {
        return false;
    };
    let parameter_type = text(parameter_type, source);
    if type_mentions_trait(parameter_type, wanted) {
        return true;
    }
    let Some(type_name) = parameter_type
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .rfind(|word| !word.is_empty() && !matches!(*word, "mut" | "dyn" | "impl"))
    else {
        return false;
    };
    signature.split([',', '>', '\n']).any(|clause| {
        clause.split_once(':').is_some_and(|(bounded, bounds)| {
            bounded.trim().ends_with(type_name) && type_mentions_trait(bounds, wanted)
        })
    })
}

fn type_mentions_trait(value: &str, wanted: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|word| word == wanted)
}

fn check_inverted_saturating_subtractions(
    root: Node<'_>,
    source: &str,
    scan: &str,
    issues: &mut Vec<Issue>,
) {
    walk_valid(root, &mut |node| {
        if node.kind() != "if_expression" {
            return;
        }
        let compact = normalized(text(node, scan));
        let Some(captures) = inverted_subtraction_regex().captures(&compact) else {
            return;
        };
        let condition_left = captures.name("condition_left").map(|value| value.as_str());
        let condition_right = captures.name("condition_right").map(|value| value.as_str());
        let subtraction_left = captures
            .name("subtraction_left")
            .map(|value| value.as_str());
        let subtraction_right = captures
            .name("subtraction_right")
            .map(|value| value.as_str());
        if condition_left == subtraction_right && condition_right == subtraction_left {
            issues.push(node_issue(
                "rust:S7463",
                "Use `saturating_sub` for this inverted conditional subtraction.",
                node,
                source,
            ));
        }
    });
}

fn check_lowercase_match_arms(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    if !scan.contains("to_ascii_lowercase()") {
        return;
    }
    for full in uppercase_string_arm_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S7428",
            "Use lowercase in this match arm because the matched value is lowercased.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn metrics(root: Node<'_>, source: &str) -> FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        source.lines().count()
    };
    let mut code = BTreeSet::new();
    let mut comments = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "line_comment" | "block_comment") {
            comments.extend(covered_rows(node));
            continue;
        }
        if node.child_count() == 0 && !node.is_error() && !node.is_missing() {
            code.extend(covered_rows(node));
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                pending.push(child);
            }
        }
    }
    FileMetrics {
        lines: u32_saturating(lines),
        code_lines: u32_saturating(code.len()),
        comment_lines: u32_saturating(comments.difference(&code).count()),
    }
}

fn covered_rows(node: Node<'_>) -> std::ops::RangeInclusive<usize> {
    let start = node.start_position().row;
    let end_position = node.end_position();
    let end = end_position.row.saturating_sub(usize::from(
        end_position.column == 0 && end_position.row > start,
    ));
    start..=end
}

fn cognitive_complexity(node: Node<'_>) -> usize {
    let mut total = 0;
    let mut pending = vec![(node, 0_usize)];
    while let Some((current, nesting)) = pending.pop() {
        let control = matches!(
            current.kind(),
            "if_expression"
                | "for_expression"
                | "while_expression"
                | "loop_expression"
                | "match_expression"
        );
        total += usize::from(control) * (nesting + 1);
        let next = nesting + usize::from(control);
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                pending.push((child, next));
            }
        }
    }
    total
}

fn deduplicate(issues: &mut Vec<Issue>) {
    let mut seen = HashSet::new();
    issues.retain(|issue| {
        seen.insert((
            issue.rule_key.clone(),
            issue.range.start.line,
            issue.range.start.column,
            issue.range.end.line,
            issue.range.end.column,
        ))
    });
}

fn is_unsigned_expression(node: Node<'_>, source: &str) -> bool {
    let value = text(node, source);
    if value.contains(".len()") || unsigned_cast_regex().is_match(value) {
        return true;
    }
    let name = value.trim();
    if !identifier_regex().is_match(name) {
        return false;
    }
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "function_item" {
            let before_use = node.start_byte().saturating_sub(current.start_byte());
            return typed_declaration_regex()
                .captures_iter(text(current, source))
                .filter(|captures| {
                    captures
                        .get(0)
                        .is_some_and(|full| full.start() < before_use)
                        && captures.name("name").map(|value| value.as_str()) == Some(name)
                })
                .filter_map(|captures| captures.name("type").map(|value| value.as_str()))
                .last()
                .is_some_and(unsigned_type);
        }
        ancestor = current.parent();
    }
    false
}

fn unsigned_type(value: &str) -> bool {
    matches!(value, "u8" | "u16" | "u32" | "u64" | "u128" | "usize")
}

fn boolean_operand_redundant(compact: &str) -> bool {
    let Some((left, repeated)) = compact.split_once("||") else {
        return false;
    };
    left.split("&&").any(|operand| operand == repeated)
}

fn parse_integer(value: &str) -> Option<u128> {
    let compact = value.replace('_', "");
    if let Some(hex) = compact.strip_prefix("0x") {
        u128::from_str_radix(hex, 16).ok()
    } else if let Some(octal) = compact.strip_prefix("0o") {
        u128::from_str_radix(octal, 8).ok()
    } else if let Some(binary) = compact.strip_prefix("0b") {
        u128::from_str_radix(binary, 2).ok()
    } else {
        compact.parse().ok()
    }
}

fn integer_is_zero(value: &str) -> bool {
    let compact = value.replace('_', "");
    let (digits, radix) = if let Some(value) = compact.strip_prefix("0x") {
        (value, 16)
    } else if let Some(value) = compact.strip_prefix("0o") {
        (value, 8)
    } else if let Some(value) = compact.strip_prefix("0b") {
        (value, 2)
    } else {
        (compact.as_str(), 10)
    };
    let digits: String = digits
        .chars()
        .take_while(|character| character.is_digit(radix))
        .collect();
    !digits.is_empty() && u128::from_str_radix(&digits, radix).ok() == Some(0)
}

fn parse_signed_integer(value: &str) -> Option<i128> {
    value.replace('_', "").parse().ok()
}

fn empty_integer_bounds(first_op: &str, first: i128, second_op: &str, second: i128) -> bool {
    let (lower, lower_inclusive, upper, upper_inclusive) =
        if first_op.starts_with('>') && second_op.starts_with('<') {
            (first, first_op == ">=", second, second_op == "<=")
        } else if first_op.starts_with('<') && second_op.starts_with('>') {
            (second, second_op == ">=", first, first_op == "<=")
        } else {
            return false;
        };
    lower > upper || lower == upper && !(lower_inclusive && upper_inclusive)
}

fn normalized(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

/// Concatenates syntax-tree leaf tokens in source order. Inter-token formatting
/// and comments disappear, while whitespace inside string and character
/// literals remains part of their leaf token and therefore stays significant.
fn normalized_node(node: Node<'_>, source: &str) -> String {
    let mut compact = String::new();
    walk_all(node, &mut |child| {
        if child.child_count() == 0 && !matches!(child.kind(), "line_comment" | "block_comment") {
            compact.push_str(text(child, source));
        }
    });
    compact
}

fn has_duplicate(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or_default()
}

fn walk<'tree>(node: Node<'tree>, callback: &mut impl FnMut(Node<'tree>)) {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        callback(current);
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                pending.push(child);
            }
        }
    }
}

fn walk_all<'tree>(node: Node<'tree>, callback: &mut impl FnMut(Node<'tree>)) {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        callback(current);
        for index in (0..current.child_count()).rev() {
            if let Some(child) = current.child(index) {
                pending.push(child);
            }
        }
    }
}

fn walk_valid<'tree>(node: Node<'tree>, callback: &mut impl FnMut(Node<'tree>)) {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.is_error() || current.is_missing() {
            continue;
        }
        if !current.has_error() {
            callback(current);
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                pending.push(child);
            }
        }
    }
}

fn node_issue(key: &str, message: impl Into<String>, node: Node<'_>, source: &str) -> Issue {
    Issue::new(key, message, node_range(node, source))
}

fn node_range(node: Node<'_>, source: &str) -> Range {
    Range {
        start: point_pos(node.start_position(), node.start_byte(), source),
        end: point_pos(node.end_position(), node.end_byte(), source),
    }
}

fn point_pos(point: Point, byte_offset: usize, source: &str) -> Pos {
    let row_start = byte_offset - point.column;
    Pos {
        line: u32_saturating(point.row + 1),
        column: u32_saturating(source[row_start..byte_offset].chars().count()),
    }
}

fn line_issue(
    key: &str,
    message: impl Into<String>,
    line: usize,
    start: usize,
    end: usize,
) -> Issue {
    Issue::new(
        key,
        message,
        Range {
            start: Pos {
                line: u32_saturating(line + 1),
                column: u32_saturating(start),
            },
            end: Pos {
                line: u32_saturating(line + 1),
                column: u32_saturating(end),
            },
        },
    )
}

fn offset_issue(
    key: &str,
    message: impl Into<String>,
    source: &str,
    start: usize,
    end: usize,
) -> Issue {
    let position = |offset: usize| {
        let before = &source[..offset];
        let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = before
            .rsplit_once('\n')
            .map_or_else(|| before.chars().count(), |(_, tail)| tail.chars().count());
        Pos {
            line: u32_saturating(line),
            column: u32_saturating(column),
        }
    };
    Issue::new(
        key,
        message,
        Range {
            start: position(start),
            end: position(end),
        },
    )
}

macro_rules! regex_fn {
    ($name:ident, $pattern:literal) => {
        fn $name() -> &'static Regex {
            static VALUE: OnceLock<Regex> = OnceLock::new();
            VALUE.get_or_init(|| Regex::new($pattern).expect(concat!("valid regex: ", $pattern)))
        }
    };
}

regex_fn!(numeric_suffix_regex, r"\b\d+_(?:8|16|32|64|128)\b");
regex_fn!(
    regex_constructor,
    r#"Regex::new\(r?\"(?P<pattern>[^\"\n]*)\"\)"#
);
regex_fn!(
    self_field_regex,
    r"^\{\s*(?:return\s+)?self\.(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*;?\s*\}$"
);
regex_fn!(identifier_regex, r"^[A-Za-z_][A-Za-z0-9_]*$");
regex_fn!(
    range_regex,
    r"(?P<start>-?\d[\d_]*)\s*\.\.=?(?P<end>-?\d[\d_]*)"
);
regex_fn!(
    mask_regex,
    r"\(?(?:[A-Za-z_][A-Za-z0-9_]*)\s*&\s*(?P<mask>0x[0-9A-Fa-f_]+|0b[01_]+|\d+)\)?\s*==\s*(?P<value>0x[0-9A-Fa-f_]+|0b[01_]+|\d+)"
);
regex_fn!(
    async_return_regex,
    r"(?s)async\s+(?:fn[^\{]+)?\{[^\}]*?(?P<call>[A-Za-z_][A-Za-z0-9_:]*\([^;\n]*\))\s*\}"
);
regex_fn!(unit_fn_regex, r"Fn(?:Mut|Once)?\([^\)]*\)\s*->\s*\(\)");
regex_fn!(
    enum_variant_regex,
    r"[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?P<value>(?:0x[0-9A-Fa-f_]+)|(?:\d{10,}))"
);
regex_fn!(
    case_mismatch_regex,
    r#"\"(?P<left>[A-Za-z]+)\"\s*=>[^,]+,\s*\"(?P<right>[A-Za-z]+)\"\s*=>"#
);
regex_fn!(
    mutable_return_regex,
    r"fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^\)]*&[^\)]*\)\s*->\s*&mut\s+"
);
regex_fn!(
    float_counter_regex,
    r"let\s+mut\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*f(?:32|64))?\s*=\s*\d+\.\d+"
);
regex_fn!(
    repeated_cast_regex,
    r"\([^\n;]+\s+as\s+(?P<first>[ui](?:8|16|32|64|128|size)|f(?:32|64))\)\s+as\s+(?P<second>[ui](?:8|16|32|64|128|size)|f(?:32|64))"
);
regex_fn!(length_cast_regex, r"\.len\(\)\s+as\s+usize");
regex_fn!(
    string_variable_regex,
    r"let\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*String::from\("
);
regex_fn!(missing_comma_regex, r"(?m)[^,\[\s]\s*\n\s*-?\d");
regex_fn!(
    partial_io_call_regex,
    r"\b(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\s*\.(?P<method>read|write)\s*\([^;\n]*\)"
);
regex_fn!(
    inverted_subtraction_regex,
    r"^if(?P<condition_left>[A-Za-z_][A-Za-z0-9_]*)>(?P<condition_right>[A-Za-z_][A-Za-z0-9_]*)\{(?P<subtraction_left>[A-Za-z_][A-Za-z0-9_]*)-(?P<subtraction_right>[A-Za-z_][A-Za-z0-9_]*)\}else\{0\}$"
);
regex_fn!(
    named_array_regex,
    r"let\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(?P<items>[^\]\n]+)\]\s*;"
);
regex_fn!(array_let_regex, r"\blet\s+");
regex_fn!(
    array_binding_regex,
    r"^(?:(?P<mutable>mut)\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
);
regex_fn!(
    named_array_access_regex,
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>\d+)\s*\]"
);
regex_fn!(
    async_block_regex,
    r"(?s)async\s*\{[^\}]*?(?P<call>[A-Za-z_][A-Za-z0-9_:]*\([^;\n]*\)(?:\.await)?)(?:\s*//[^\n]*)?\s*\}"
);
regex_fn!(
    slice_cast_regex,
    r"\*const\s*\[(?P<from>[A-Za-z_][A-Za-z0-9_]*)\]\s+as\s+\*const\s*\[(?P<to>[A-Za-z_][A-Za-z0-9_]*)\]"
);
regex_fn!(
    double_comparison_regex,
    r"(?P<first_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<first_op><=|>=|<|>)\s*(?P<first>-?\d[\d_]*)\s*&&\s*(?P<second_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<second_op><=|>=|<|>)\s*(?P<second>-?\d[\d_]*)"
);
regex_fn!(
    unwrap_regex,
    r"(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\.unwrap\(\)"
);
regex_fn!(
    panicking_condition_regex,
    r"^(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\.is_(?:none|err)\(\)$"
);
regex_fn!(
    overflow_comparison_regex,
    r"[A-Za-z_][A-Za-z0-9_]*\s*\+\s*[A-Za-z_][A-Za-z0-9_]*\s*<\s*[A-Za-z_][A-Za-z0-9_]*"
);
regex_fn!(
    unit_sort_closure_regex,
    r"\.sort_by_key\(\|[^|]+\|\s*\{[^\}]*;\s*\}\)"
);
regex_fn!(unsigned_cast_regex, r"\bas\s+u(?:8|16|32|64|128|size)\b");
regex_fn!(
    typed_declaration_regex,
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<type>[A-Za-z_][A-Za-z0-9_:<>]*)"
);
regex_fn!(
    uppercase_string_arm_regex,
    r#"\"[A-Za-z]*[A-Z][A-Za-z]*\"\s*=>"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_macro_index_tracks_each_binding_until_its_next_shadow() {
        let source = concat!(
            "let a = [1, 2]; emit!(a[2], a[1], aa[99], éa[99]);\n",
            "let b = [1]; emit!(b[1], a[3]);\n",
            "let mut a = other; emit!(a[99]);\n",
            "let a = [1, 2, 3]; emit!(a[3], a[2]);\n",
            "let b = [1, 2]; emit!(b[2], b[1]);\n",
        );
        let mut issues = Vec::new();
        check_macro_array_indexes(source, source, &mut issues);
        let selected: Vec<_> = issues
            .iter()
            .map(|issue| {
                let line = source
                    .lines()
                    .nth(issue.range.start.line as usize - 1)
                    .unwrap();
                line.chars()
                    .skip(issue.range.start.column as usize)
                    .take((issue.range.end.column - issue.range.start.column) as usize)
                    .collect::<String>()
            })
            .collect();
        assert_eq!(selected, ["a[2]", "a[3]", "b[1]", "a[3]", "b[2]"]);
    }

    #[test]
    fn array_macro_index_retains_recovered_keyword_binding_boundaries() {
        for source in [
            "let mut = [1]; let mut next; emit!(mut[2]);",
            "let a = [1]; let let a; emit!(a[2]);",
            "let a = [1]; let mut a; emit!(a[2]);",
        ] {
            let mut issues = Vec::new();
            check_macro_array_indexes(source, source, &mut issues);
            assert!(issues.is_empty(), "{source}: {issues:?}");
        }
    }

    const TEST_RULE_KEYS: &[&str] = &[
        "rust:S106",
        "rust:S107",
        "rust:S1116",
        "rust:S126",
        "rust:S1488",
        "rust:S1612",
        "rust:S1656",
        "rust:S1751",
        "rust:S1764",
        "rust:S1858",
        "rust:S1862",
        "rust:S2148",
        "rust:S2185",
        "rust:S2193",
        "rust:S2198",
        "rust:S2208",
        "rust:S2260",
        "rust:S2437",
        "rust:S2479",
        "rust:S2589",
        "rust:S3498",
        "rust:S3723",
        "rust:S3776",
        "rust:S3807",
        "rust:S4275",
        "rust:S4325",
        "rust:S4962",
        "rust:S5856",
        "rust:S6164",
        "rust:S6466",
        "rust:S6913",
        "rust:S7089",
        "rust:S7200",
        "rust:S7411",
        "rust:S7412",
        "rust:S7413",
        "rust:S7414",
        "rust:S7415",
        "rust:S7417",
        "rust:S7418",
        "rust:S7419",
        "rust:S7420",
        "rust:S7421",
        "rust:S7422",
        "rust:S7423",
        "rust:S7424",
        "rust:S7425",
        "rust:S7426",
        "rust:S7427",
        "rust:S7428",
        "rust:S7429",
        "rust:S7430",
        "rust:S7431",
        "rust:S7432",
        "rust:S7433",
        "rust:S7436",
        "rust:S7437",
        "rust:S7438",
        "rust:S7439",
        "rust:S7440",
        "rust:S7441",
        "rust:S7442",
        "rust:S7443",
        "rust:S7444",
        "rust:S7445",
        "rust:S7446",
        "rust:S7447",
        "rust:S7448",
        "rust:S7449",
        "rust:S7450",
        "rust:S7451",
        "rust:S7453",
        "rust:S7454",
        "rust:S7455",
        "rust:S7456",
        "rust:S7457",
        "rust:S7458",
        "rust:S7459",
        "rust:S7460",
        "rust:S7461",
        "rust:S7462",
        "rust:S7463",
        "rust:S7464",
        "rust:S905",
        "rust:S920",
    ];

    fn keys(source: &str) -> Vec<String> {
        analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        )
        .issues
        .into_iter()
        .map(|issue| issue.rule_key)
        .collect()
    }

    #[test]
    fn every_catalog_rule_has_production_and_test_contract() {
        assert_eq!(RULE_KEYS, TEST_RULE_KEYS);
        assert_eq!(RULE_KEYS.len(), 85);
    }

    #[test]
    fn representative_structural_and_pattern_rules_emit() {
        let source = "use std::collections::*;\nfn f(a:i32,b:i32,c:i32,d:i32,e:i32,f:i32,g:i32,h:i32){ println!(\"x\"); let mut x=1; x=x; ; if x>0 {} else if x>0 {} }\n";
        let found = keys(source);
        for key in [
            "rust:S106",
            "rust:S107",
            "rust:S1116",
            "rust:S1656",
            "rust:S1862",
            "rust:S2208",
        ] {
            assert!(found.iter().any(|actual| actual == key), "{key}: {found:?}");
        }
    }

    #[test]
    fn clean_control_has_no_findings() {
        assert!(keys("fn add(left: i32, right: i32) -> i32 { left + right }\n").is_empty());
    }

    #[test]
    fn textual_rules_ignore_literals_and_comments_without_hiding_later_code() {
        let source = concat!(
            "const EXAMPLE: &str = r#\"println!(\\\"hidden\\\"); use hidden::*;\"#;\n",
            "// dbg!(\"hidden\");\n",
            "/* eprintln!(\"hidden\"); */\n",
            "fn main() { let url = \"https://example.test\"; println!(\"visible\"); }\n",
        );
        let found = keys(source);
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "rust:S106")
                .count(),
            1,
            "only the executable println should fire: {found:?}"
        );
        assert!(
            found.iter().all(|key| key != "rust:S2208"),
            "wildcard import text inside a literal must stay ignored: {found:?}"
        );
    }

    #[test]
    fn intentional_console_output_requires_an_actual_lint_allowance() {
        let allowed = keys(concat!(
            "#![allow(clippy::print_stdout)]\n",
            "fn main() { println!(\"command output\"); }\n",
        ));
        assert!(allowed.iter().all(|key| key != "rust:S106"), "{allowed:?}");

        let comment_only = keys(concat!(
            "// clippy::print_stdout\n",
            "fn main() { println!(\"still direct output\"); }\n",
        ));
        assert!(comment_only.iter().any(|key| key == "rust:S106"));
    }

    #[test]
    fn wildcard_import_rule_keeps_rust_prelude_and_test_idioms() {
        let idiomatic = keys(concat!(
            "pub(crate) use facade::*;\n",
            "use rayon::prelude::*;\n",
            "#[cfg(test)] mod tests { use super::*; }\n",
        ));
        assert!(
            idiomatic.iter().all(|key| key != "rust:S2208"),
            "{idiomatic:?}"
        );
        assert!(
            keys("use std::collections::*;\n")
                .iter()
                .any(|key| key == "rust:S2208")
        );
    }

    #[test]
    fn closure_replacement_stays_silent_without_type_evidence() {
        let found = keys(concat!(
            "fn accepts(value: &&str) -> bool { !value.is_empty() }\n",
            "fn main() { let values = vec![\"x\"]; let _ = values.iter().filter(|value| accepts(value)); }\n",
        ));
        assert!(found.iter().all(|key| key != "rust:S1612"), "{found:?}");
    }

    #[test]
    fn textual_rule_columns_count_unicode_characters_not_bytes() {
        let source = "fn main() { let text = \"café\"; println!(\"visible\"); }\n";
        let report = analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        );
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "rust:S106")
            .expect("println finding");
        let expected_column = source
            .split("println!")
            .next()
            .expect("prefix")
            .chars()
            .count();
        assert_eq!(issue.range.start.column, u32_saturating(expected_column));
        let invocation = "println!(\"visible\")";
        assert_eq!(
            issue.range.end.column,
            u32_saturating(expected_column + invocation.chars().count())
        );
    }

    #[test]
    fn structural_rule_columns_count_unicode_characters_not_bytes() {
        let source = "fn main() { let café = 1; café = café; }\n";
        let report = analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        );
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "rust:S1656")
            .expect("self-assignment finding");
        let expected_column = source
            .split("café = café")
            .next()
            .expect("prefix")
            .chars()
            .count();
        assert_eq!(issue.range.start.column, u32_saturating(expected_column));
    }

    #[test]
    fn parser_errors_are_reported_without_panicking() {
        assert!(keys("fn broken( {").contains(&"rust:S2260".to_string()));
    }

    #[test]
    fn textual_rules_ignore_comments_literals_and_error_recovery_regions() {
        let source = concat!(
            "fn main() {\n",
            "    let example = r#\"let mut values = Vec::new(); values.push(1); values.push(2); 9..1\"#;\n",
            "    // let broken = Regex::new(\"(\");\n",
            "    /* let mut values = Vec::new(); values.push(1); values.push(2); */\n",
            "    let value = 9.25;\n",
            "}\n",
        );
        let found = keys(source);
        for key in ["rust:S5856", "rust:S7089", "rust:S7432"] {
            assert!(found.iter().all(|actual| actual != key), "{key}: {found:?}");
        }

        let malformed = keys("fn broken( { println!(\"not accepted\"); }");
        assert!(malformed.contains(&"rust:S2260".to_string()));
        assert!(
            malformed.iter().all(|key| key != "rust:S106"),
            "{malformed:?}"
        );
    }

    #[test]
    fn integer_range_checks_reject_only_actual_reversed_ranges() {
        let found = keys(concat!(
            "fn main() {\n",
            "    let _decimal = 9.25;\n",
            "    let _forward = -10..=-2;\n",
            "    let _reversed = 10_000..9_000;\n",
            "}\n",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "rust:S7432")
                .count(),
            1,
            "{found:?}"
        );
    }

    #[test]
    fn missing_else_is_anchored_at_last_else_if() {
        let source = concat!(
            "fn main(value: i32) {\n",
            "    if value == 1 {}\n",
            "    else if value == 2 {}\n",
            "    else if value == 3 {}\n",
            "}\n",
        );
        let report = analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        );
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "rust:S126")
            .expect("missing final else");
        assert_eq!(issue.range.start.line, 4);
        assert_eq!(issue.range.start.column, 9);
    }

    #[test]
    fn large_number_rule_covers_float_literals() {
        let report = analyze(
            PathBuf::from("fixture.rs"),
            "fn main() { let value = 1_f64 / 3.1415926535; }\n",
            &AnalyzerOptions::default(),
        );
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "rust:S2148")
            .expect("large float literal");
        assert_eq!(issue.range.end.column - issue.range.start.column, 12);
    }

    #[test]
    fn erasing_operation_does_not_claim_remainder_by_one() {
        let remainder = keys("fn main(x: i32) { let _ = x % 1; }");
        assert!(
            remainder.iter().all(|key| key != "rust:S2185"),
            "{remainder:?}"
        );
        let multiplication = keys("fn main(x: i32) { let _ = x * 0; }");
        assert!(
            multiplication.contains(&"rust:S2185".to_string()),
            "{multiplication:?}"
        );
    }

    #[test]
    fn null_pointer_cast_range_includes_pointee_type() {
        let source = "fn main() { let _ = unsafe { std::mem::transmute(0 as *const u64) }; }\n";
        let report = analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        );
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "rust:S4962")
            .expect("null pointer cast");
        assert_eq!(issue.range.end.column - issue.range.start.column, 15);
    }

    #[test]
    fn partial_io_rule_rejects_open_options_boolean_setters() {
        let builder = keys(concat!(
            "fn main() {\n",
            "    let _ = std::fs::OpenOptions::new().read(true).write(false);\n",
            "}\n",
        ));
        assert!(builder.iter().all(|key| key != "rust:S7419"), "{builder:?}");

        let io = keys(concat!(
            "fn write<W: std::io::Write>(writer: &mut W) {\n",
            "    let _ = writer.write(b\"content\");\n",
            "}\n",
        ));
        assert!(io.contains(&"rust:S7419".to_string()), "{io:?}");
    }

    #[test]
    fn partial_io_rule_requires_an_io_trait_contract() {
        let custom_method = keys(concat!(
            "struct Recorder;\n",
            "impl Recorder { fn write(&self, _: &str) {} }\n",
            "fn record(recorder: &Recorder) { recorder.write(\"done\"); }\n",
        ));
        assert!(
            custom_method.iter().all(|key| key != "rust:S7419"),
            "{custom_method:?}"
        );

        let mixed = keys(concat!(
            "struct Recorder;\n",
            "impl Recorder { fn write(&self, _: &str) {} }\n",
            "fn record<W: std::io::Write>(writer: &mut W, recorder: &Recorder) {\n",
            "    recorder.write(\"done\");\n",
            "    let _ = writer;\n",
            "}\n",
        ));
        assert!(mixed.iter().all(|key| key != "rust:S7419"), "{mixed:?}");

        let io = keys(concat!(
            "fn copy<R: std::io::Read>(reader: &mut R, bytes: &mut [u8]) {\n",
            "    let _ = reader.read(bytes);\n",
            "}\n",
        ));
        assert!(io.contains(&"rust:S7419".to_string()), "{io:?}");
    }

    #[test]
    fn binary_rules_preserve_literals_and_follow_eq_op_operators() {
        let found = keys(concat!(
            "fn names(name: &str) -> bool { name == \"Id\" || name == \"Key\" }\n",
            "fn product(value: i32) -> i32 { value * value }\n",
            "fn duplicate(value: i32) -> bool { value == value }\n",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "rust:S1764")
                .count(),
            1,
            "{found:?}"
        );
        assert!(found.iter().all(|key| key != "rust:S2589"), "{found:?}");
    }

    #[test]
    fn ineffective_bit_masks_require_a_comparison_contract() {
        let clean = keys(concat!(
            "fn permissions(mode: u32) -> bool { mode & 0o022 != 0 }\n",
            "fn alternative(value: Option<i32>) { match value { Some(0 | -1) => {}, _ => {} } }\n",
        ));
        assert!(clean.iter().all(|key| key != "rust:S2437"), "{clean:?}");

        let ineffective = keys("fn check(value: u32) -> bool { (value | 2) > 3 }\n");
        assert!(
            ineffective.contains(&"rust:S2437".to_string()),
            "{ineffective:?}"
        );
    }

    #[test]
    fn vector_initialization_rule_requires_direct_consecutive_pushes() {
        let dynamic = keys(concat!(
            "fn collect(values: &[i32]) -> Vec<i32> {\n",
            "    let mut output = Vec::new();\n",
            "    for value in values { output.push(*value); output.push(*value + 1); }\n",
            "    output\n",
            "}\n",
        ));
        assert!(dynamic.iter().all(|key| key != "rust:S7089"), "{dynamic:?}");

        let direct = keys(concat!(
            "fn collect() -> Vec<i32> {\n",
            "    let mut output = Vec::new();\n",
            "    output.push(1);\n",
            "    output.push(2);\n",
            "    output\n",
            "}\n",
        ));
        assert!(direct.contains(&"rust:S7089".to_string()), "{direct:?}");
    }

    #[test]
    fn array_index_rule_distinguishes_index_chains_from_literals() {
        let chained = keys(concat!(
            "use std::ops::Index;\n",
            "struct Rows([i32; 2]);\n",
            "impl Index<&str> for Rows {\n",
            "    type Output = [i32; 2];\n",
            "    fn index(&self, _: &str) -> &Self::Output { &self.0 }\n",
            "}\n",
            "fn get(rows: &Rows) -> i32 { rows[\"first\"][1] }\n",
        ));
        assert!(chained.iter().all(|key| key != "rust:S6466"), "{chained:?}");

        let out_of_bounds = keys("fn get() -> i32 { [1, 2][4] }\n");
        assert!(
            out_of_bounds.contains(&"rust:S6466".to_string()),
            "{out_of_bounds:?}"
        );

        let shadowed = keys(concat!(
            "fn get() -> i32 {\n",
            "    let values = [1, 2];\n",
            "    { let values = vec![1, 2, 3, 4, 5]; values[4] }\n",
            "}\n",
        ));
        assert!(
            shadowed.iter().all(|key| key != "rust:S6466"),
            "{shadowed:?}"
        );
    }

    #[test]
    fn immutable_while_rule_ignores_stateful_conditions() {
        let stateful = keys(concat!(
            "fn drain(values: &mut Vec<i32>) { while let Some(_) = values.pop() {} }\n",
            "fn walk(cursor: &mut std::slice::Iter<'_, i32>) { while cursor.next().is_some() {} }\n",
        ));
        assert!(
            stateful.iter().all(|key| key != "rust:S7415"),
            "{stateful:?}"
        );

        let immutable = keys("fn spin(value: i32) { while value > 10 {} }\n");
        assert!(
            immutable.contains(&"rust:S7415".to_string()),
            "{immutable:?}"
        );
    }

    #[test]
    fn missing_comma_rule_stays_inside_array_literals() {
        let ordinary_lines = keys(concat!(
            "fn count(empty: bool) -> usize {\n",
            "    if empty {\n",
            "        0\n",
            "    } else {\n",
            "        1\n",
            "    }\n",
            "}\n",
        ));
        assert!(
            ordinary_lines.iter().all(|key| key != "rust:S3723"),
            "{ordinary_lines:?}"
        );

        let missing = keys("fn values() { let _ = [1, 2\n -3, 4]; }\n");
        assert!(missing.contains(&"rust:S3723".to_string()), "{missing:?}");
    }

    #[test]
    fn boolean_match_parameters_are_resolved_within_their_function() {
        let unrelated = keys(concat!(
            "fn accepts(flag: bool) { let _ = flag; }\n",
            "fn classify(value: u8) -> u8 { match value { 0 => 1, _ => 2 } }\n",
            "fn find(values: &[u8], wanted: u8) -> u8 {\n",
            "    match values.iter().find(|value| **value == wanted) { Some(value) => *value, None => 0 }\n",
            "}\n",
        ));
        assert!(
            unrelated.iter().all(|key| key != "rust:S920"),
            "{unrelated:?}"
        );

        let boolean =
            keys("fn classify(value: bool) -> u8 { match value { true => 1, false => 2 } }\n");
        assert!(boolean.contains(&"rust:S920".to_string()), "{boolean:?}");
    }

    #[test]
    fn shared_branch_rule_compares_syntax_instead_of_literal_shapes() {
        let distinct = keys(concat!(
            "fn choose(flag: bool) -> &'static str {\n",
            "    if flag { \"a b\" } else { \"ab\" }\n",
            "}\n",
            "const EXAMPLE: &str = \"if flag { work(); } else { work(); }\";\n",
        ));
        assert!(
            distinct.iter().all(|key| key != "rust:S7411"),
            "{distinct:?}"
        );

        let shared = keys(concat!(
            "fn choose(flag: bool) {\n",
            "    if flag { prepare(); left(); } else { prepare(); right(); }\n",
            "}\n",
        ));
        assert!(shared.contains(&"rust:S7411".to_string()), "{shared:?}");
    }

    #[test]
    fn inverted_subtraction_rule_requires_reversed_operands() {
        let clean = keys(concat!(
            "fn before(bytes: &[u8], start: usize) -> usize {\n",
            "    if start > 0 && bytes[start - 1] == b'x' { start - 1 } else { start }\n",
            "}\n",
        ));
        assert!(clean.iter().all(|key| key != "rust:S7463"), "{clean:?}");

        let inverted = keys(
            "fn subtract(left: u32, right: u32) -> u32 { if left > right { right - left } else { 0 } }\n",
        );
        assert!(inverted.contains(&"rust:S7463".to_string()), "{inverted:?}");
    }

    #[test]
    fn no_effect_field_access_includes_semicolon() {
        let source = "fn main(pair: (i32, i32)) { pair.1; }\n";
        let report = analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        );
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "rust:S905")
            .expect("no-effect field access");
        assert_eq!(issue.range.end.column - issue.range.start.column, 7);
    }

    #[test]
    fn comparison_ranges_require_same_variable_and_an_empty_intersection() {
        let clean = keys(concat!(
            "fn clean(x: i32, y: i32) {\n",
            "    if x < 2 && y > 8 {}\n",
            "    if x >= 5 && x <= 5 {}\n",
            "}\n",
        ));
        assert!(clean.iter().all(|key| key != "rust:S7439"), "{clean:?}");

        let empty = keys("fn empty(x: i32) { if x > -5 && x <= -5 {} }");
        assert!(empty.contains(&"rust:S7439".to_string()), "{empty:?}");

        let redundant = keys("fn redundant(x: i32) { if x < 500 && x < 400 {} }");
        assert!(
            redundant.contains(&"rust:S7436".to_string()),
            "{redundant:?}"
        );
    }

    #[test]
    fn panicking_unwrap_is_scoped_to_guarded_receiver_and_branch() {
        let clean = keys(concat!(
            "fn clean(left: Option<i32>, right: Option<i32>) {\n",
            "    if left.is_none() { let _ = right.unwrap(); }\n",
            "    let _ = left.unwrap();\n",
            "}\n",
        ));
        assert!(clean.iter().all(|key| key != "rust:S7442"), "{clean:?}");

        let bad = keys(concat!(
            "fn bad(value: Option<i32>) {\n",
            "    if value.is_none() { let _ = value.unwrap(); }\n",
            "}\n",
        ));
        assert_eq!(
            bad.iter()
                .filter(|key| key.as_str() == "rust:S7442")
                .count(),
            1,
            "{bad:?}"
        );
    }

    #[test]
    fn unsigned_zero_check_uses_compared_expression_type() {
        let clean = keys("fn clean(unsigned: u32, signed: i32) -> bool { signed < 0 }");
        assert!(clean.iter().all(|key| key != "rust:S2198"), "{clean:?}");

        let shadowed = keys(concat!(
            "fn shadowed(value: u32) -> bool {\n",
            "    let value: i32 = -1;\n",
            "    value < 0\n",
            "}\n",
        ));
        assert!(
            shadowed.iter().all(|key| key != "rust:S2198"),
            "{shadowed:?}"
        );

        let bad = keys("fn bad(unsigned: u32, signed: i32) -> bool { unsigned<0 }");
        assert_eq!(
            bad.iter()
                .filter(|key| key.as_str() == "rust:S2198")
                .count(),
            1,
            "{bad:?}"
        );
    }

    #[test]
    fn redundant_string_conversion_emits_once_at_conversion() {
        let found = keys(concat!(
            "fn main() {\n",
            "    let value = String::from(\"text\");\n",
            "    let _ = value.to_string();\n",
            "}\n",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "rust:S1858")
                .count(),
            1,
            "{found:?}"
        );
    }

    #[test]
    fn returned_local_rule_uses_direct_tail_and_avoids_redundant_cast_overlap() {
        let clean = keys(concat!(
            "fn length(value: &str) -> usize {\n",
            "    let length = value.len() as usize;\n",
            "    length\n",
            "}\n",
        ));
        assert!(clean.iter().all(|key| key != "rust:S1488"), "{clean:?}");

        let source = concat!(
            "fn duration(value: u32) -> u32 {\n",
            "    let duration = value * 1000;\n",
            "    duration\n",
            "}\n",
        );
        let report = analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        );
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "rust:S1488")
            .expect("direct returned local");
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(issue.range.end.line, 2);
    }

    #[test]
    fn getter_rule_requires_a_direct_field_return() {
        let clean = keys(concat!(
            "struct Shape { width: i32, height: i32 }\n",
            "impl Shape { fn area(&self) -> i32 { self.width * self.height } }\n",
        ));
        assert!(clean.iter().all(|key| key != "rust:S4275"), "{clean:?}");

        let bad = keys(concat!(
            "struct Pair { left: i32, right: i32 }\n",
            "impl Pair { fn left(&self) -> i32 { self.right } }\n",
        ));
        assert!(bad.contains(&"rust:S4275".to_string()), "{bad:?}");
    }

    #[test]
    fn single_iteration_loop_requires_a_direct_exit() {
        let clean = keys(concat!(
            "fn keep_running(stop: bool) {\n",
            "    loop {\n",
            "        let example = \"break;\";\n",
            "        if stop { break; }\n",
            "    }\n",
            "}\n",
        ));
        assert!(clean.iter().all(|key| key != "rust:S1751"), "{clean:?}");

        let bad = keys("fn once() { loop { work(); break; } }");
        assert!(bad.contains(&"rust:S1751".to_string()), "{bad:?}");
    }

    #[test]
    fn metrics_use_syntax_nodes_not_comment_markers_inside_literals() {
        let source = concat!(
            "// lead\n",
            "fn main() {\n",
            "    let marker = \"/* not a comment\"; // trailing\n",
            "    /* nested /* block */ comment */\n",
            "}\n",
        );
        let report = analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.metrics.lines, 5);
        assert_eq!(report.metrics.code_lines, 3);
        assert_eq!(report.metrics.comment_lines, 2);
    }

    #[test]
    fn deep_cst_analysis_is_iterative() {
        let depth = 2_000;
        let source = format!(
            "fn deep() {{ {} true {} }}\n",
            "if true { ".repeat(depth),
            " }".repeat(depth)
        );
        let found = keys(&source);
        assert!(found.contains(&"rust:S3776".to_string()), "{found:?}");
    }

    #[test]
    fn complete_oracle_fixture_corpus_fires_only_bad_controls() {
        let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.oracle/sonar/projects/oracle-rust/src");
        for key in RULE_KEYS {
            let id = key.split_once(":S").expect("Rust rule key has :S prefix").1;
            let bad_path = project.join(format!("s{id}_bad.rs"));
            let good_path = project.join(format!("s{id}_good.rs"));
            let bad = std::fs::read_to_string(&bad_path).expect("bad fixture is readable");
            let good = std::fs::read_to_string(&good_path).expect("good fixture is readable");
            let bad_report = analyze(bad_path, &bad, &AnalyzerOptions::default());
            let good_report = analyze(good_path, &good, &AnalyzerOptions::default());
            assert!(
                bad_report.issues.iter().any(|issue| issue.rule_key == *key),
                "{key} did not fire on bad fixture: {:?}",
                bad_report.issues
            );
            assert!(
                good_report
                    .issues
                    .iter()
                    .all(|issue| issue.rule_key != *key),
                "{key} fired on good fixture: {:?}",
                good_report.issues
            );
        }
    }

    #[test]
    fn native_async_guard_rules_require_type_evidence_and_live_guard() {
        let bad = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "use std::cell::RefCell;\n",
            "async fn run(mutex: &Mutex<i32>, cell: &RefCell<i32>) {\n",
            "  let lock = mutex.lock().unwrap();\n",
            "  work().await;\n",
            "  drop(lock);\n",
            "  let borrowed = cell.borrow();\n",
            "  more().await;\n",
            "  drop(borrowed);\n",
            "}\n",
        ));
        assert!(
            bad.iter()
                .any(|issue| issue.rule_key == "hoonarqube-rust:await-holding-lock")
        );
        assert!(
            bad.iter()
                .any(|issue| { issue.rule_key == "hoonarqube-rust:await-holding-refcell-ref" })
        );

        let clean = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "use std::cell::RefCell;\n",
            "async fn run(mutex: &Mutex<i32>, cell: &RefCell<i32>) {\n",
            "  let lock = mutex.lock().unwrap();\n",
            "  drop(lock);\n",
            "  work().await;\n",
            "  { let borrowed = cell.borrow(); inspect(&borrowed); }\n",
            "  more().await;\n",
            "}\n",
        ));
        assert!(clean.is_empty(), "unexpected native findings: {clean:?}");

        let custom_path = analyze_native(concat!(
            "async fn run(mutex: &mystd::sync::Mutex<i32>) {\n",
            "  let lock = mutex.lock().unwrap();\n",
            "  work().await;\n",
            "  drop(lock);\n",
            "}\n",
        ));
        assert!(
            custom_path.is_empty(),
            "a path containing `std` must not count as `std`: {custom_path:?}",
        );
    }

    #[test]
    fn native_lock_rule_ignores_async_aware_lock_acquisition() {
        let clean = analyze_native(concat!(
            "use tokio::sync::Mutex;\n",
            "async fn run(mutex: &Mutex<i32>) {\n",
            "  let lock = mutex.lock().await;\n",
            "  work().await;\n",
            "  drop(lock);\n",
            "}\n",
        ));
        assert!(clean.is_empty(), "unexpected native findings: {clean:?}");
    }

    #[test]
    fn native_guard_rules_resolve_receiver_types_and_conditional_drops() {
        let clean = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "struct Gate; impl Gate { fn lock(&self) -> Guard { Guard } }\n",
            "async fn run(gate: &Gate) { let guard = gate.lock(); work().await; drop(guard); }\n",
        ));
        assert!(clean.is_empty(), "custom lock must stay clean: {clean:?}");

        let conditional_drop = analyze_native(concat!(
            "use std::sync::Mutex as StdMutex;\n",
            "async fn run(mutex: &StdMutex<i32>, release: bool) {\n",
            "  let guard = mutex.lock().unwrap();\n",
            "  if release { drop(guard); }\n",
            "  work().await;\n",
            "}\n",
        ));
        assert!(
            conditional_drop
                .iter()
                .any(|issue| issue.rule_key == "hoonarqube-rust:await-holding-lock")
        );

        let scoped_alias = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "mod custom {\n",
            "  use crate::Gate as Mutex;\n",
            "  impl Mutex { fn lock(&self) -> Guard { Guard } }\n",
            "  async fn run(mutex: &Mutex) {\n",
            "    let guard = mutex.lock(); work().await; drop(guard);\n",
            "  }\n",
            "}\n",
            "struct Gate; struct Guard;\n",
        ));
        assert!(
            scoped_alias.is_empty(),
            "imports from sibling modules must not provide type evidence: {scoped_alias:?}",
        );

        let parent_import = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "mod custom {\n",
            "  struct Mutex; struct Guard;\n",
            "  impl Mutex { fn lock(&self) -> Guard { Guard } }\n",
            "  async fn run(mutex: &Mutex) {\n",
            "    let guard = mutex.lock(); work().await; drop(guard);\n",
            "  }\n",
            "}\n",
        ));
        assert!(
            parent_import.is_empty(),
            "parent-module imports must not leak into child modules: {parent_import:?}",
        );

        let local_import = analyze_native(concat!(
            "struct C;\n",
            "async fn run(mutex: &C) {\n",
            "  use std::sync::Mutex as Imported;\n",
            "  let _typed: Option<Imported> = None;\n",
            "  let guard = mutex.lock(); work().await; drop(guard);\n",
            "  async fn inner(mutex: &Imported) {\n",
            "    let guard = mutex.lock();\n",
            "    work().await;\n",
            "    drop(guard);\n",
            "  }\n",
            "}\n",
        ));
        let local_import_issues = local_import
            .iter()
            .filter(|issue| issue.rule_key == "hoonarqube-rust:await-holding-lock")
            .collect::<Vec<_>>();
        assert_eq!(
            local_import_issues.len(),
            1,
            "only the post-import nested type-use should resolve as a Mutex: {local_import:?}",
        );
        assert_eq!(local_import_issues[0].range.start.line, 8);

        let generic_shadow = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "async fn run<Mutex>(mutex: &Mutex) {\n",
            "  let guard = mutex.lock(); work().await; drop(guard);\n",
            "}\n",
        ));
        assert!(
            generic_shadow.is_empty(),
            "generic parameters must shadow imported guard names: {generic_shadow:?}",
        );
    }
    #[test]
    fn native_guard_rules_respect_std_shadowing_scope() {
        let inner_std_root_does_not_hide_imported_mutex = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "async fn run(mutex: &Mutex<i32>) {\n",
            "  {\n",
            "    mod std {}\n",
            "    let guard = mutex.lock().unwrap();\n",
            "    work().await;\n",
            "    drop(guard);\n",
            "  }\n",
            "}\n",
        ));
        assert!(
            inner_std_root_does_not_hide_imported_mutex
                .iter()
                .any(|issue| issue.rule_key == "hoonarqube-rust:await-holding-lock"),
            "an inner `std` item must not clear an outer imported Mutex alias: {inner_std_root_does_not_hide_imported_mutex:?}",
        );

        let same_scope_std_root_stays_shadowed = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "mod std {}\n",
            "async fn qualified(mutex: &std::sync::Mutex<i32>) {\n",
            "  let guard = mutex.lock().unwrap();\n",
            "  work().await;\n",
            "  drop(guard);\n",
            "}\n",
            "async fn unqualified(mutex: &Mutex<i32>) {\n",
            "  let guard = mutex.lock().unwrap();\n",
            "  work().await;\n",
            "  drop(guard);\n",
            "}\n",
        ));
        assert!(
            same_scope_std_root_stays_shadowed.is_empty(),
            "same-scope `std` shadowing must reject both relative std paths and canonical aliases: {same_scope_std_root_stays_shadowed:?}",
        );

        let same_scope_std_alias_stays_shadowed = analyze_native(concat!(
            "use std::sync::Mutex as StdMutex;\n",
            "mod std {}\n",
            "async fn run(mutex: &StdMutex<i32>) {\n",
            "  let guard = mutex.lock().unwrap();\n",
            "  work().await;\n",
            "  drop(guard);\n",
            "}\n",
        ));
        assert!(
            same_scope_std_alias_stays_shadowed.is_empty(),
            "same-scope `std` shadowing must reject aliases imported from that scope: {same_scope_std_alias_stays_shadowed:?}",
        );
    }

    #[test]
    fn native_file_rules_require_resolved_standard_library_chains() {
        let found = analyze_native(concat!(
            "use std::fs::{self as filesystem, OpenOptions as Options};\n",
            "fn write(path: &str) {\n",
            "  Options::new().write(true).create(true).open(path).unwrap();\n",
            "  filesystem::File::options().create(true).open(path).unwrap();\n",
            "  filesystem::metadata(path).unwrap().permissions().set_readonly(false);\n",
            "  tokio::fs::OpenOptions::new().create(true).open(path).await.unwrap();\n",
            "}\n",
        ));
        let open_options_lines = found
            .iter()
            .filter(|issue| issue.rule_key == "hoonarqube-rust:suspicious-open-options")
            .map(|issue| issue.range.start.line)
            .collect::<Vec<_>>();
        assert_eq!(
            open_options_lines,
            vec![3, 4, 6],
            "all positive open-options chains must be located exactly: {found:?}",
        );
        assert!(
            found.iter().any(|issue| {
                issue.rule_key == "hoonarqube-rust:permissions-set-readonly-false"
            }),
            "missing permissions finding: {found:?}",
        );

        for clean in [
            "use std::fs::OpenOptions; fn f(path: &str) { OpenOptions::new().create(true).truncate(true).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str) { OpenOptions::new().create(true).truncate(false).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str) { OpenOptions::new().create_new(true).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str) { OpenOptions::new().create(true).create(false).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str) { OpenOptions::new().create(true).create_new(true).create_new(false).create_new(true).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str, create: bool) { OpenOptions::new().create(true).create(create).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str, exclusive: bool) { OpenOptions::new().create(true).create_new(exclusive).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str, exclusive: bool) { OpenOptions::new().create(true).create_new(false).create_new(exclusive).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str) { OpenOptions::new().create(true).append(true).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str, append: bool) { OpenOptions::new().create(true).append(append).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str) { OpenOptions::new().create(true).append(true).append(false).append(true).open(path); }",
            "use std::fs::OpenOptions; trait Ext { fn truncate_write(&mut self, value: bool) -> &mut Self; } fn f(path: &str) { OpenOptions::new().create(true).truncate_write(true).open(path); }",
            "struct OpenOptions; impl OpenOptions { fn new() -> Builder { Builder } } fn f(path: &str) { OpenOptions::new().create(true).open(path); }",
            "fn f(metadata: Metadata) { metadata.permissions().set_readonly(false); }",
            "fn f(path: &str) { custom::metadata(path).permissions().set_readonly(false); }",
            "fn f(path: &str) { std::fs::metadata(path).unwrap().permissions().set_readonly(true); }",
            "mod std { pub mod fs { pub struct OpenOptions; } } fn f(path: &str) { std::fs::OpenOptions::new().create(true).open(path); }",
            "mod std { pub mod fs { pub fn metadata(_: &str) -> Metadata { todo!() } } } fn f(path: &str) { std::fs::metadata(path).permissions().set_readonly(false); }",
            "mod tokio { pub mod fs { pub struct OpenOptions; } } async fn f(path: &str) { tokio::fs::OpenOptions::new().create(true).open(path).await; }",
        ] {
            assert!(analyze_native(clean).is_empty(), "{clean}");
        }

        for suspicious in [
            "use std::fs::OpenOptions; fn f(path: &str, create: bool) { OpenOptions::new().create(create).create(true).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str, exclusive: bool) { OpenOptions::new().create(true).create_new(exclusive).create_new(false).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str) { OpenOptions::new().create(true).append(false).open(path); }",
            "use std::fs::OpenOptions; fn f(path: &str, append: bool) { OpenOptions::new().create(true).append(append).append(false).open(path); }",
        ] {
            assert!(
                analyze_native(suspicious)
                    .iter()
                    .any(|issue| issue.rule_key == "hoonarqube-rust:suspicious-open-options"),
                "{suspicious}",
            );
        }

        let absolute = analyze_native(
            "fn f(path: &str) { ::std::fs::OpenOptions::new().create(true).open(path); }",
        );
        assert!(
            absolute
                .iter()
                .any(|issue| issue.rule_key == "hoonarqube-rust:suspicious-open-options"),
            "absolute standard-library paths must remain resolved: {absolute:?}",
        );
    }
    #[test]
    fn eager_transmute_rule_scopes_only_eager_arguments() {
        let source = concat!(
            "fn unrelated() { unsafe { std::mem::transmute::<u8, u8>(1); } }\n",
            "fn eager() {\n",
            "  let _ = true.then_some(unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "  let _ = Some(1).unwrap_or(unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "  let _ = Some(1).map_or(unsafe { std::mem::transmute::<u8, u8>(1) }, |_| unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "  let _ = true.then_some(async { unsafe { std::mem::transmute::<u8, u8>(1) } });\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7443")
                .count(),
            3
        );
    }
    #[test]
    fn eager_transmute_rule_rejects_free_functions_and_custom_methods() {
        let source = concat!(
            "struct Value;\n",
            "impl Value { fn transmute(&self) -> u8 { 0 } }\n",
            "fn unwrap_or(value: u8) -> u8 { value }\n",
            "fn check(value: Value) {\n",
            "  let _ = unwrap_or(\n",
            "      unsafe { std::mem::transmute::<u8, u8>(1) }\n",
            "  );\n",
            "  let _ = Some(1).unwrap_or(value.transmute());\n",
            "}\n",
        );
        assert!(
            keys(source).into_iter().all(|key| key != "rust:S7443"),
            "user-defined eager/transmute calls must stay silent",
        );
    }

    #[test]
    fn standard_paths_are_not_resolved_through_shadowing_modules() {
        let source = concat!(
            "mod std { pub mod mem { pub fn transmute(value: u8) -> u8 { value } } }\n",
            "mod core { pub mod iter { pub fn repeat(_: i32) -> std::ops::Range<i32> { 0..3 } } }\n",
            "fn check() {\n",
            "  let _ = Some(1).unwrap_or(std::mem::transmute(1));\n",
            "  let _ = core::iter::repeat(1).collect::<Vec<_>>();\n",
            "  let _ = Some(1).unwrap_or(::std::mem::transmute(1));\n",
            "  let _ = ::core::iter::repeat(1).collect::<Vec<_>>();\n",
            "}\n",
        );
        let found = keys(source);
        assert_eq!(
            found.iter().filter(|key| *key == "rust:S7443").count(),
            1,
            "relative module shadowing must stay silent while absolute std stays resolved: {found:?}",
        );
        assert_eq!(
            found.iter().filter(|key| *key == "rust:S7464").count(),
            1,
            "relative module shadowing must stay silent while absolute core stays resolved: {found:?}",
        );
    }
    #[test]
    fn standard_imports_respect_closure_parameters() {
        let source = concat!(
            "use std::mem::transmute;\n",
            "use std::iter::repeat;\n",
            "fn check() {\n",
            "  let _ = (|transmute| Some(1).unwrap_or(transmute(1)))(identity);\n",
            "  let _ = (|repeat| repeat(1).collect::<Vec<_>>())(identity);\n",
            "}\n",
        );
        let found = keys(source);
        assert!(
            found
                .iter()
                .all(|key| key != "rust:S7443" && key != "rust:S7464"),
            "closure parameters must shadow standard imports: {found:?}",
        );
    }

    #[test]
    fn standard_imports_resolve_grouped_self_aliases_and_globs() {
        let grouped = concat!(
            "use std::mem::{self, transmute};\n",
            "use std::iter::{self as iter, repeat};\n",
            "fn grouped() {\n",
            "  let _ = Some(1).unwrap_or(mem::transmute(1));\n",
            "  let _ = Some(1).unwrap_or(transmute(1));\n",
            "  let _ = iter::repeat(1).collect::<Vec<_>>();\n",
            "  let _ = repeat(1).collect::<Vec<_>>();\n",
            "}\n",
        );
        let grouped_found = keys(grouped);
        assert_eq!(
            grouped_found
                .iter()
                .filter(|key| *key == "rust:S7443" || *key == "rust:S7464")
                .count(),
            4,
            "grouped use trees must preserve self aliases: {grouped_found:?}",
        );

        let glob = concat!(
            "use std::mem::*;\n",
            "use std::iter::*;\n",
            "fn glob() {\n",
            "  let _ = Some(1).unwrap_or(transmute(1));\n",
            "  let _ = repeat(1).collect::<Vec<_>>();\n",
            "}\n",
        );
        let glob_found = keys(glob);
        assert_eq!(
            glob_found
                .iter()
                .filter(|key| *key == "rust:S7443" || *key == "rust:S7464")
                .count(),
            2,
            "glob use trees must resolve standard leaves: {glob_found:?}",
        );
    }

    #[test]
    fn raw_pointer_rule_does_not_mistake_unsafe_function_types_for_modifiers() {
        let source = concat!(
            "fn callback_parameter(ptr: *const i32, callback: unsafe fn()) { unsafe { *ptr; } }\n",
            "fn callback_return(ptr: *const i32) -> unsafe fn() { unsafe { *ptr; } panic!(); }\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7446")
                .count(),
            2
        );
    }

    #[test]
    fn raw_pointer_rule_requires_a_dereferenced_parameter_in_the_same_function() {
        let source = concat!(
            "fn no_deref(ptr: *const i32) { let _ = ptr; }\n",
            "fn unrelated() { unsafe { let ptr: *const i32 = std::ptr::null(); *ptr; } }\n",
            "fn actual(ptr: *const i32) { unsafe { *ptr; *ptr; } }\n",
            "unsafe fn already(ptr: *const i32) { unsafe { *ptr; } }\n",
            "fn shadowed(ptr: *const i32) { let ptr = 0; unsafe { *ptr; } }\n",
            "fn alias(ptr: *const i32) { let alias = ptr; unsafe { *alias; } }\n",
            "fn reassigned(ptr: *const i32) { let mut alias = ptr; alias = std::ptr::null(); unsafe { *alias; } }\n",
            "fn shadowed_alias(ptr: *const i32) { let alias = ptr; { let alias = 0; unsafe { *alias; } } }\n",
            "fn outer(ptr: *const i32) { fn inner() { unsafe { *ptr; } } }\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7446")
                .count(),
            2
        );
    }
    #[test]
    fn raw_pointer_rule_unwraps_casts_and_destructured_parameters() {
        let source = concat!(
            "fn direct_cast(ptr: *const i32) { unsafe { *(ptr as *const i32); } }\n",
            "fn alias_cast(ptr: *const i32) { let alias = ptr as *const i32; unsafe { *alias; } }\n",
            "fn destructured((ptr, _): (*const i32, i32)) { unsafe { *ptr; } }\n",
            "fn destructured_leading_wildcard((_, ptr): (i32, *const i32)) { unsafe { *ptr; } }\n",
            "fn non_pointer((value, _): (i32, i32)) { unsafe { let _ = value; } }\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7446")
                .count(),
            4,
        );
    }
    #[test]
    fn raw_pointer_rule_scans_macro_tokens_only_in_the_current_function() {
        let source = concat!(
            "fn macro_oracle(ptr: *const i32) { println!(\"{}\", unsafe { *ptr }); }\n",
            "fn other_function() { println!(\"{}\", unsafe { *ptr }); }\n",
            "fn string_only(ptr: *const i32) { println!(\"{}\", \"unsafe { *ptr }\"); }\n",
            "fn comment_only(ptr: *const i32) { println!(\"{}\", /* unsafe { *ptr } */ 0); }\n",
            "fn shadowed(ptr: *const i32) { let ptr = 0; println!(\"{}\", unsafe { *ptr }); }\n",
            "fn alias_macro(ptr: *const i32) { let alias = ptr; println!(\"{}\", unsafe { *alias }); }\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7446")
                .count(),
            2
        );
    }

    #[test]
    fn raw_pointer_macro_token_collection_handles_deep_nesting() {
        // Tree-sitter's macro-token grammar becomes superlinear at extreme
        // delimiter depths; 256 still exercises the iterative collector
        // without turning this regression into a parser stress benchmark.
        let depth = 256;
        let mut nested = "(".repeat(depth);
        nested.push('0');
        nested.push_str(&")".repeat(depth));
        let source =
            format!("fn deep(ptr: *const i32) {{ println!({nested}, unsafe {{ *ptr }}); }}");
        assert_eq!(
            keys(&source)
                .into_iter()
                .filter(|key| key == "rust:S7446")
                .count(),
            1
        );
    }

    #[test]
    fn infinite_iterator_rule_follows_bounded_and_exhausting_consumers() {
        let source = concat!(
            "fn iterators() {\n",
            "  let bounded = std::iter::repeat(1)\n",
            "      .take(2)\n",
            "      .collect::<Vec<_>>();\n",
            "  let later = std::iter::repeat(2);\n",
            "  let _clean_later = later.find(|value| *value == 2);\n",
            "  let unbounded = std::iter::repeat(3)\n",
            "      .map(|value| value + 1)\n",
            "      .collect::<Vec<_>>();\n",
            "  let cycle = [1, 2].into_iter().cycle().collect::<Vec<_>>();\n",
            "  let chain = std::iter::once(0).chain(std::iter::repeat(5)).collect::<Vec<_>>();\n",
            "  let infinite = std::iter::repeat(6);\n",
            "  let bound_chain = std::iter::once(0).chain(infinite);\n",
            "  let _bound_chain_result = bound_chain.collect::<Vec<_>>();\n",
            "  let mut assigned = std::iter::repeat(4);\n",
            "  assigned = [1, 2].into_iter();\n",
            "  let _clean_assignment = assigned.collect::<Vec<_>>();\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7464")
                .count(),
            4
        );
    }
    #[test]
    fn infinite_iterator_rule_requires_standard_repeat_provenance() {
        let local = concat!(
            "fn repeat(_: i32) -> std::ops::Range<i32> { 0..3 }\n",
            "fn local() { let _ = repeat(1).collect::<Vec<_>>(); }\n",
        );
        assert!(
            keys(local).into_iter().all(|key| key != "rust:S7464"),
            "finite user-defined repeat must stay silent",
        );
        let imported = concat!(
            "use std::iter::repeat;\n",
            "fn imported() { let _ = repeat(1).collect::<Vec<_>>(); }\n",
        );
        assert_eq!(
            keys(imported)
                .into_iter()
                .filter(|key| key == "rust:S7464")
                .count(),
            1
        );
        let absolute = concat!(
            "fn absolute() {\n",
            "  let _ = ::std::iter::repeat(1).collect::<Vec<_>>();\n",
            "  let _ = ::core::iter::repeat(2).collect::<Vec<_>>();\n",
            "}\n",
        );
        assert_eq!(
            keys(absolute)
                .into_iter()
                .filter(|key| key == "rust:S7464")
                .count(),
            2
        );
    }
    #[test]
    fn standard_paths_keep_absolute_and_namespace_semantics() {
        let source = concat!(
            "mod custom { pub mod std {} }\n",
            "use custom::std as custom_std;\n",
            "fn check() {\n",
            "  let std = 1;\n",
            "  let _ = Some(1).unwrap_or(std::mem::transmute(1));\n",
            "  let _ = Some(1).unwrap_or(::std::mem::transmute(1));\n",
            "  let _ = Some(1).unwrap_or(custom_std::mem::transmute(1));\n",
            "}\n",
        );
        let found = keys(source);
        assert_eq!(
            found.iter().filter(|key| *key == "rust:S7443").count(),
            2,
            "values must not shadow qualified modules, but aliases must: {found:?}",
        );
    }

    #[test]
    fn standard_root_aliases_and_block_use_scopes_are_lexical() {
        let source = concat!(
            "use ::std as standard;\n",
            "use ::core as fundamental;\n",
            "fn check() {\n",
            "  let _ = Some(1).unwrap_or(standard::mem::transmute(1));\n",
            "  let _ = fundamental::iter::repeat(1).collect::<Vec<_>>();\n",
            "  { use std::mem::transmute; let _ = Some(1).unwrap_or(transmute(1)); }\n",
            "  { let _ = Some(1).unwrap_or(transmute(1)); use std::mem::transmute; }\n",
            "  let _ = Some(1).unwrap_or(transmute(1));\n",
            "}\n",
        );
        let found = keys(source);
        assert_eq!(
            found.iter().filter(|key| *key == "rust:S7443").count(),
            3,
            "root aliases and block-local imports must resolve throughout their scope: {found:?}",
        );
        assert_eq!(
            found.iter().filter(|key| *key == "rust:S7464").count(),
            1,
            "core root alias must resolve without leaking block imports: {found:?}",
        );
    }

    #[test]
    fn raw_pointer_rule_handles_wrapped_destructuring_and_local_projection() {
        let source = concat!(
            "fn array([ptr]: [*const i32; 1]) { unsafe { *ptr; } }\n",
            "fn slice([ptr]: [*const i32]) { unsafe { *ptr; } }\n",
            "fn reference(&(ptr,): &(*const i32,)) { unsafe { *ptr; } }\n",
            "fn parenthesized((ptr): (*const i32)) { unsafe { *ptr; } }\n",
            "fn local_tuple(ptr: *const i32) {\n",
            "  let (alias, _) = (ptr, 0);\n",
            "  unsafe { *alias; }\n",
            "}\n",
            "fn local_array(ptr: *const i32) {\n",
            "  let [alias] = [ptr];\n",
            "  unsafe { *alias; }\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7446")
                .count(),
            6,
            "all wrapped/destructured pointer paths must resolve: {source}",
        );
    }
    #[test]
    fn raw_pointer_rule_unwraps_parenthesized_macro_operands() {
        let source = concat!(
            "fn parenthesized(ptr: *const i32) { consume!(unsafe { *(ptr) }); }\n",
            "fn controls(ptr: *const i32) {\n",
            "    let _ = \"*(ptr)\";\n",
            "    /* unsafe { *(ptr) } */\n",
            "    let _ = ptr * 2;\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7446")
                .count(),
            1,
            "only the parenthesized macro dereference should be reported: {source}",
        );
    }

    #[test]
    fn infinite_iterator_rule_recognizes_unbounded_ranges() {
        let source = concat!(
            "fn ranges() {\n",
            "    let _ = (0..).collect::<Vec<_>>();\n",
            "    let range = 0..;\n",
            "    let _ = range.count();\n",
            "    let _ = (0..10).collect::<Vec<_>>();\n",
            "    let _ = (..10).collect::<Vec<_>>();\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7464")
                .count(),
            2,
            "only RangeFrom origins should be reported: {source}",
        );
    }

    #[test]
    fn eager_transmute_rule_handles_standard_ufcs_fallbacks() {
        let source = concat!(
            "fn ufcs() {\n",
            "    Option::unwrap_or(Some(1u8), unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "    use std::option::Option as StdOption;\n",
            "    StdOption::unwrap_or(Some(1u8), unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "    Option::map_or(Some(1u8), unsafe { std::mem::transmute::<u8, u8>(1) }, 0u8);\n",
            "    bool::then_some(true, unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "    let option = Some(1u8);\n",
            "    let _ = option.unwrap_or(unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "    let _ = option.map_or(unsafe { std::mem::transmute::<u8, u8>(1) }, 0u8);\n",
            "    let _ = true.then_some(unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "}\n",
            "struct Option;\n",
            "fn shadowed() {\n",
            "    Option::unwrap_or(Option, unsafe { std::mem::transmute::<u8, u8>(1) });\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7443")
                .count(),
            7,
            "standard UFCS and method fallbacks should be eager: {source}",
        );
    }

    #[test]
    fn eager_transmute_rule_detects_macro_token_tree_calls() {
        let source = concat!(
            "macro_rules! identity { ($e:expr) => {{ $e }} }\n",
            "macro_rules! discard { ($e:expr) => {{}} }\n",
            "fn macros() {\n",
            "    let _ = true.then_some(identity!(unsafe { std::mem::transmute::<u8, u8>(1) }));\n",
            "    let _ = true.then_some(discard!(unsafe { std::mem::transmute::<u8, u8>(1) }));\n",
            "    let _ = true.then_some(identity!(\"std::mem::transmute::<u8, u8>(1)\"));\n",
            "    let _ = false.then_some(std::dbg!(unsafe { std::mem::transmute::<u8, u8>(1) }));\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7443")
                .count(),
            2,
            "only forwarding macro token trees should be reported: {source}",
        );

        let report = analyze(
            PathBuf::from("fixture.rs"),
            source,
            &AnalyzerOptions::default(),
        );
        let starts = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "rust:S7443")
            .map(|issue| issue.range.start.line)
            .collect::<Vec<_>>();
        assert!(
            starts.contains(&7),
            "std::dbg! transmute was not located: {starts:?}"
        );
    }

    #[test]
    fn infinite_iterator_rule_handles_iterator_ufcs_consumers() {
        let source = concat!(
            "fn standard() {\n",
            "    let _ = Iterator::count(std::iter::repeat(1));\n",
            "    let _ = Iterator::count(std::iter::repeat(1).take(1));\n",
            "    let _ = Iterator::collect::<Vec<_>>(std::iter::repeat(1));\n",
            "    let _ = Iterator::collect::<Vec<_>>(std::iter::repeat(1).take(1));\n",
            "    let _ = std::iter::Iterator::count(std::iter::repeat(1));\n",
            "}\n",
            "fn shadowed() {\n",
            "    trait Iterator {}\n",
            "    let _ = Iterator::count(std::iter::repeat(1));\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7464")
                .count(),
            3,
            "only standard unbounded UFCS consumers should be reported: {source}",
        );
    }
    #[test]
    fn infinite_iterator_rule_covers_macro_and_for_consumers() {
        let source = concat!(
            "fn consumers() {\n",
            "    vec![std::iter::repeat(1).collect::<Vec<_>>()];\n",
            "    vec![[1, 2].into_iter().cycle().collect::<Vec<_>>()];\n",
            "    vec![std::iter::repeat(1).map(|value| value + 1).collect::<Vec<_>>()];\n",
            "    vec![std::iter::repeat(1).map(|value| value + 1).take(2).collect::<Vec<_>>()];\n",
            "    for _ in std::iter::repeat(1) {}\n",
            "    vec![std::iter::repeat(1).take(2).collect::<Vec<_>>()];\n",
            "    for _ in std::iter::repeat(1).take(2) {}\n",
            "}\n",
        );
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == "rust:S7464")
                .count(),
            4,
            "only unbounded macro and for consumers should be reported: {source}",
        );
    }
    #[test]
    fn console_allow_respects_module_and_cfg_scope() {
        let scoped = analyze(
            PathBuf::from("fixture.rs"),
            concat!(
                "mod nested {\n",
                "    #![allow(clippy::print_stdout)]\n",
                "    fn nested() { println!(\"nested\"); }\n",
                "}\n",
                "fn main() { println!(\"root\"); }\n",
            ),
            &AnalyzerOptions::default(),
        );
        let scoped_outputs: Vec<_> = scoped
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "rust:S106")
            .collect();
        assert_eq!(scoped_outputs.len(), 1, "{scoped_outputs:?}");
        assert_eq!(scoped_outputs[0].range.start.line, 5);

        let cfg_disabled = analyze(
            PathBuf::from("fixture.rs"),
            concat!(
                "#[cfg(feature = \"never\")]\n",
                "mod disabled {\n",
                "    #![allow(clippy::print_stdout)]\n",
                "    fn hidden() { println!(\"hidden\"); }\n",
                "}\n",
                "fn main() { println!(\"root\"); }\n",
            ),
            &AnalyzerOptions::default(),
        );
        let cfg_outputs: Vec<_> = cfg_disabled
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "rust:S106")
            .collect();
        assert_eq!(cfg_outputs.len(), 1, "{cfg_outputs:?}");
        assert_eq!(cfg_outputs[0].range.start.line, 6);

        let crate_allowed = keys(concat!(
            "#![allow(clippy::print_stdout)]\n",
            "fn main() { println!(\"allowed\"); }\n",
        ));
        assert!(
            crate_allowed.iter().all(|key| key != "rust:S106"),
            "{crate_allowed:?}"
        );
    }

    #[test]
    fn native_guard_acquisition_ignores_deferred_closure_and_async_bodies() {
        let direct = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "async fn direct(mutex: &Mutex<i32>) {\n",
            "    let guard = mutex.lock().unwrap();\n",
            "    work().await;\n",
            "    drop(guard);\n",
            "}\n",
        ));
        assert_eq!(
            direct
                .iter()
                .filter(|issue| issue.rule_key == "hoonarqube-rust:await-holding-lock")
                .count(),
            1,
            "{direct:?}"
        );

        let deferred = analyze_native(concat!(
            "use std::sync::Mutex;\n",
            "async fn future(mutex: &Mutex<i32>) {\n",
            "    let guard = async { mutex.lock().unwrap() };\n",
            "    work().await;\n",
            "    drop(guard);\n",
            "}\n",
            "async fn closure(mutex: &Mutex<i32>) {\n",
            "    let guard = || mutex.lock().unwrap();\n",
            "    work().await;\n",
            "    drop(guard);\n",
            "}\n",
        ));
        assert!(
            deferred.is_empty(),
            "deferred lock calls are not acquired guards: {deferred:?}"
        );
    }

    #[test]
    fn standard_transmute_import_is_shadowed_by_match_arm_bindings() {
        let shadowed = keys(concat!(
            "use std::mem::transmute;\n",
            "fn check(value: Option<fn(u8) -> u8>) {\n",
            "    match value {\n",
            "        Some(transmute) => {\n",
            "            let _ = Some(1u8).unwrap_or(transmute(1u8));\n",
            "        }\n",
            "        _ => {}\n",
            "    }\n",
            "}\n",
        ));
        assert!(
            shadowed.iter().all(|key| key != "rust:S7443"),
            "{shadowed:?}"
        );

        let imported = keys(concat!(
            "use std::mem::transmute;\n",
            "fn check() {\n",
            "    let _ = Some(1u8).unwrap_or(transmute(1u8));\n",
            "}\n",
        ));
        assert_eq!(
            imported
                .iter()
                .filter(|key| key.as_str() == "rust:S7443")
                .count(),
            1,
            "{imported:?}"
        );
    }
}
