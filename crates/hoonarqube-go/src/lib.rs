//! Tolerant Go analyzer for the frozen `SonarQube` Community Go catalog.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use hoonarqube_dataflow::{
    ControlFlowSpec, Direction, TaintFacts, build_from_blocks, solve_dataflow,
};
use hoonarqube_ir::{
    FileMetrics, FileReport, FlowLocation, Issue, Pos, Range, sort_issues, u32_saturating,
};
use tree_sitter::{Node, Parser, Point};

/// Go rule parameters exposed by the frozen catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: usize,
    pub maximum_lines_of_code: usize,
    pub maximum_expression_complexity: usize,
    pub maximum_function_parameters: usize,
    pub maximum_case_lines: usize,
    pub duplicate_string_threshold: usize,
    pub maximum_nesting_depth: usize,
    pub maximum_function_lines: usize,
    pub maximum_switch_cases: usize,
    pub maximum_cognitive_complexity: usize,
    pub header_format: String,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 120,
            maximum_lines_of_code: 750,
            maximum_expression_complexity: 3,
            maximum_function_parameters: 7,
            maximum_case_lines: 6,
            duplicate_string_threshold: 3,
            maximum_nesting_depth: 4,
            maximum_function_lines: 120,
            maximum_switch_cases: 30,
            maximum_cognitive_complexity: 15,
            header_format: String::new(),
        }
    }
}

const RULE_KEYS: &[&str] = &[
    "go:S100", "go:S103", "go:S104", "go:S1067", "go:S107", "go:S108", "go:S1110", "go:S1125",
    "go:S1134", "go:S1135", "go:S1145", "go:S1151", "go:S117", "go:S1186", "go:S1192", "go:S122",
    "go:S126", "go:S131", "go:S1314", "go:S134", "go:S138", "go:S1451", "go:S1479", "go:S1656",
    "go:S1763", "go:S1764", "go:S1821", "go:S1862", "go:S1871", "go:S1940", "go:S2260", "go:S2757",
    "go:S3776", "go:S3923", "go:S4144", "go:S4663",
];

/// Analyze one Go source file. Syntax-invalid files fail closed with only
/// `go:S2260` findings; semantic rules never run on recovered fragments.
///
/// # Panics
///
/// Panics only if the embedded Tree-sitter Go grammar is incompatible or the
/// parser cannot return a syntax tree.
#[must_use]
pub fn analyze(path: PathBuf, source: &str, options: &AnalyzerOptions) -> FileReport {
    debug_assert_eq!(RULE_KEYS.len(), 36);
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("tree-sitter-go language is compatible");
    let tree = parser
        .parse(source, None)
        .expect("Go parser returned no tree");
    let root = tree.root_node();
    let line_facts = LineFacts::collect(source, root);
    let mut issues = Vec::new();

    check_syntax_errors(root, source, &mut issues);
    if !issues.is_empty() {
        sort_issues(&mut issues);
        issues.dedup();
        return FileReport {
            path,
            language: "go".to_string(),
            issues,
            metrics: metrics(source, &line_facts),
        };
    }

    check_lines(path.as_path(), source, &line_facts, options, &mut issues);
    check_header(source, options, &mut issues);
    check_textual(source, root, &mut issues);
    walk(root, &mut |node| {
        check_node(node, source, &line_facts, options, &mut issues);
    });
    check_duplicate_strings(root, source, options, &mut issues);
    check_duplicate_functions(root, source, &mut issues);
    sort_issues(&mut issues);
    issues.dedup();

    FileReport {
        path,
        language: "go".to_string(),
        issues,
        metrics: metrics(source, &line_facts),
    }
}

/// Runs independently implemented, non-Sonar Go rules. Callers select the
/// active profile and filter these findings through `hoonarqube-catalog`.
/// Syntax-invalid input produces no native findings.
#[must_use]
pub fn analyze_native(source: &str) -> Vec<Issue> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
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

    let imports = GoImports::collect(root, source);
    let mut issues = Vec::new();
    check_native_bidi_controls(source, &mut issues);
    check_native_import_rules(root, source, &imports, &mut issues);
    walk(root, &mut |node| {
        check_native_node(node, source, &imports, &mut issues);
    });
    check_native_nil_contexts(root, source, &imports, &mut issues);
    check_native_archive_paths(root, source, &imports, &mut issues);
    check_native_decompression_flows(root, source, &imports, &mut issues);
    sort_issues(&mut issues);
    issues.dedup();
    issues
}

#[derive(Debug, Default)]
struct GoImports {
    aliases: HashMap<String, String>,
    dot_imports: HashSet<String>,
}

impl GoImports {
    fn collect(root: Node<'_>, source: &str) -> Self {
        let mut imports = Self::default();
        walk(root, &mut |node| {
            if node.kind() != "import_spec" {
                return;
            }
            let Some(path_node) = node.child_by_field_name("path") else {
                return;
            };
            let path = text(path_node, source).trim_matches(['"', '`']);
            let package = path.rsplit('/').next().unwrap_or(path);
            match node
                .child_by_field_name("name")
                .map(|name| text(name, source))
            {
                Some("_") => {}
                Some(".") => {
                    imports.dot_imports.insert(path.to_string());
                }
                Some(alias) => {
                    imports.aliases.insert(path.to_string(), alias.to_string());
                }
                None => {
                    imports
                        .aliases
                        .insert(path.to_string(), package.to_string());
                }
            }
        });
        imports
    }

    fn alias(&self, path: &str) -> Option<&str> {
        self.aliases.get(path).map(String::as_str)
    }

    fn qualified(&self, path: &str, member: &str) -> Option<String> {
        Some(format!("{}.{member}", self.alias(path)?))
    }

    fn non_blank_import(&self, path: &str) -> bool {
        self.aliases.contains_key(path) || self.dot_imports.contains(path)
    }
}

fn check_native_node(node: Node<'_>, source: &str, imports: &GoImports, issues: &mut Vec<Issue>) {
    match node.kind() {
        "call_expression" => check_native_call(node, source, imports, issues),
        "composite_literal" => check_native_composite(node, source, imports, issues),
        "field_declaration" => check_native_serialized_secret(node, source, issues),
        "go_statement" => check_native_waitgroup_add(node, source, imports, issues),
        "expression_statement" => check_native_discarded_append(node, source, issues),
        "statement_list" => {
            check_native_lock_sequence(node, source, issues);
            check_native_statement_flow(node, source, imports, issues);
        }
        "for_statement" => check_native_loop(node, source, imports, issues),
        _ => {}
    }
}

fn check_native_bidi_controls(source: &str, issues: &mut Vec<Issue>) {
    const BIDI_CONTROLS: &[char] = &[
        '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
        '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ];
    for (offset, character) in source.char_indices() {
        if !BIDI_CONTROLS.contains(&character) {
            continue;
        }
        issues.push(offset_issue(
            "hoonarqube-go:G116",
            "Remove this bidirectional Unicode control character.",
            source,
            offset,
            offset + character.len_utf8(),
        ));
    }
}

fn check_native_import_rules(
    root: Node<'_>,
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    for (path, key, message) in [
        (
            "crypto/md5",
            "hoonarqube-go:G401",
            "Replace MD5 with a cryptographically strong hash.",
        ),
        (
            "crypto/sha1",
            "hoonarqube-go:G401",
            "Replace SHA-1 with a cryptographically strong hash.",
        ),
        (
            "crypto/des",
            "hoonarqube-go:G405",
            "Replace DES with a modern authenticated cipher.",
        ),
        (
            "crypto/rc4",
            "hoonarqube-go:G405",
            "Replace RC4 with a modern authenticated cipher.",
        ),
        (
            "golang.org/x/crypto/md4",
            "hoonarqube-go:G406",
            "Replace MD4 with a cryptographically strong hash.",
        ),
        (
            "golang.org/x/crypto/ripemd160",
            "hoonarqube-go:G406",
            "Replace RIPEMD-160 with a cryptographically strong hash.",
        ),
    ] {
        if !imports.non_blank_import(path) {
            continue;
        }
        walk(root, &mut |node| {
            if node.kind() == "import_spec"
                && node
                    .child_by_field_name("path")
                    .is_some_and(|value| text(value, source).trim_matches(['"', '`']) == path)
            {
                issues.push(node_issue(key, message, node, source));
            }
        });
    }
}

fn check_native_call(node: Node<'_>, source: &str, imports: &GoImports, issues: &mut Vec<Issue>) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let function_name = text(function, source);

    if let Some(http) = imports.alias("net/http")
        && ["Serve", "ListenAndServe", "ListenAndServeTLS"]
            .iter()
            .any(|member| function_name == format!("{http}.{member}"))
    {
        issues.push(node_issue(
            "hoonarqube-go:G114",
            "Use an http.Server with explicit timeouts instead of this package-level serving helper.",
            function,
            source,
        ));
    }

    let arguments = node
        .child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default();
    if imports
        .qualified("time", "Sleep")
        .is_some_and(|sleep| function_name == sleep)
        && let [duration] = arguments.as_slice()
        && duration.kind() == "int_literal"
        && parse_go_integer(text(*duration, source)).is_some_and(|value| (1..=120).contains(&value))
    {
        issues.push(node_issue(
            "hoonarqube-go:SA1004",
            "Multiply this small Sleep duration by an explicit time unit.",
            *duration,
            source,
        ));
    }
    check_native_os_call(function, function_name, &arguments, source, imports, issues);
    check_native_ioutil_call(function_name, &arguments, source, imports, issues);
    check_native_rsa_call(function_name, &arguments, source, imports, issues);
}

fn check_native_os_call(
    function: Node<'_>,
    function_name: &str,
    arguments: &[Node<'_>],
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    if let Some(os) = imports.alias("os") {
        let permission_rule = match function_name {
            name if name == format!("{os}.Mkdir") || name == format!("{os}.MkdirAll") => {
                arguments.get(1).map(|argument| {
                    (
                        argument,
                        0o750,
                        "hoonarqube-go:G301",
                        "Restrict directory permissions to 0750 or less.",
                    )
                })
            }
            name if name == format!("{os}.Chmod") => arguments.get(1).map(|argument| {
                (
                    argument,
                    0o600,
                    "hoonarqube-go:G302",
                    "Restrict file permissions to 0600 or less.",
                )
            }),
            name if name == format!("{os}.WriteFile") => arguments.get(2).map(|argument| {
                (
                    argument,
                    0o600,
                    "hoonarqube-go:G306",
                    "Restrict written-file permissions to 0600 or less.",
                )
            }),
            _ => None,
        };
        if let Some((argument, allowed, key, message)) = permission_rule
            && parse_go_integer(text(*argument, source)).is_some_and(|mode| mode & !allowed != 0)
        {
            issues.push(node_issue(key, message, *argument, source));
        }
        if function_name == format!("{os}.Create") {
            issues.push(node_issue(
                "hoonarqube-go:G307",
                "Use os.OpenFile with an explicit 0600 mode under the strict profile.",
                function,
                source,
            ));
        }
        if (function_name == format!("{os}.Create") || function_name == format!("{os}.WriteFile"))
            && arguments
                .first()
                .is_some_and(|argument| is_predictable_temp_path(*argument, source, imports))
        {
            issues.push(node_issue(
                "hoonarqube-go:G303",
                "Create a randomized temporary file instead of using this predictable shared path.",
                arguments[0],
                source,
            ));
        }
    }
}

fn check_native_ioutil_call(
    function_name: &str,
    arguments: &[Node<'_>],
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    if let Some(ioutil) = imports.alias("io/ioutil")
        && function_name == format!("{ioutil}.WriteFile")
        && let Some(argument) = arguments.get(2)
        && parse_go_integer(text(*argument, source)).is_some_and(|mode| mode & !0o600 != 0)
    {
        issues.push(node_issue(
            "hoonarqube-go:G306",
            "Restrict written-file permissions to 0600 or less.",
            *argument,
            source,
        ));
    }
    if let Some(ioutil) = imports.alias("io/ioutil")
        && function_name == format!("{ioutil}.WriteFile")
        && arguments
            .first()
            .is_some_and(|argument| is_predictable_temp_path(*argument, source, imports))
    {
        issues.push(node_issue(
            "hoonarqube-go:G303",
            "Create a randomized temporary file instead of using this predictable shared path.",
            arguments[0],
            source,
        ));
    }
}

fn check_native_rsa_call(
    function_name: &str,
    arguments: &[Node<'_>],
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    if let Some(rsa) = imports.alias("crypto/rsa")
        && function_name == format!("{rsa}.GenerateKey")
        && let Some(bits) = arguments.get(1)
        && parse_go_integer(text(*bits, source)).is_some_and(|bits| bits < 2048)
    {
        issues.push(node_issue(
            "hoonarqube-go:G403",
            "Generate RSA keys with at least 2048 bits.",
            *bits,
            source,
        ));
    }
}

fn is_predictable_temp_path(node: Node<'_>, source: &str, imports: &GoImports) -> bool {
    match node.kind() {
        "interpreted_string_literal" | "raw_string_literal" => {
            let value = text(node, source).trim_matches(['"', '`']);
            value == "/tmp"
                || value.starts_with("/tmp/")
                || value == "/usr/tmp"
                || value.starts_with("/usr/tmp/")
                || value == "/var/tmp"
                || value.starts_with("/var/tmp/")
        }
        "binary_expression" => node
            .child_by_field_name("left")
            .is_some_and(|left| is_predictable_temp_path(left, source, imports)),
        "call_expression" => {
            let function = node
                .child_by_field_name("function")
                .map(|function| text(function, source));
            if imports
                .qualified("os", "TempDir")
                .as_deref()
                .is_some_and(|temp_dir| function == Some(temp_dir))
            {
                return true;
            }
            let is_join = ["path", "path/filepath"].into_iter().any(|package| {
                imports
                    .qualified(package, "Join")
                    .as_deref()
                    .is_some_and(|join| function == Some(join))
            });
            is_join
                && node
                    .child_by_field_name("arguments")
                    .and_then(first_named)
                    .is_some_and(|argument| is_predictable_temp_path(argument, source, imports))
        }
        "parenthesized_expression" => {
            first_named(node).is_some_and(|inner| is_predictable_temp_path(inner, source, imports))
        }
        _ => false,
    }
}

fn check_native_nil_contexts(
    root: Node<'_>,
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    let Some(context_alias) = imports.alias("context") else {
        return;
    };
    let mut known = collect_local_context_parameters(root, source, context_alias);
    if let Some(exec) = imports.alias("os/exec") {
        known.insert(format!("{exec}.CommandContext"), vec![0]);
    }
    if let Some(http) = imports.alias("net/http") {
        known.insert(format!("{http}.NewRequestWithContext"), vec![0]);
    }
    report_nil_context_arguments(root, source, &known, issues);
}

fn collect_local_context_parameters(
    root: Node<'_>,
    source: &str,
    context_alias: &str,
) -> HashMap<String, Vec<usize>> {
    let mut local_context_parameters = HashMap::<String, Vec<usize>>::new();
    walk(root, &mut |node| {
        if node.kind() != "function_declaration" {
            return;
        }
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return;
        };
        let mut indexes = Vec::new();
        let mut index = 0;
        for parameter in named_children(parameters) {
            if parameter.kind() != "parameter_declaration" {
                continue;
            }
            let names: Vec<_> = {
                let mut cursor = parameter.walk();
                parameter
                    .children_by_field_name("name", &mut cursor)
                    .collect()
            };
            let is_context = parameter
                .child_by_field_name("type")
                .is_some_and(|kind| text(kind, source) == format!("{context_alias}.Context"));
            for _ in &names {
                if is_context {
                    indexes.push(index);
                }
                index += 1;
            }
        }
        if !indexes.is_empty() {
            local_context_parameters.insert(text(name, source).to_string(), indexes);
        }
    });
    local_context_parameters
}

fn report_nil_context_arguments(
    root: Node<'_>,
    source: &str,
    known: &HashMap<String, Vec<usize>>,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let Some(indexes) = known.get(text(function, source)) else {
            return;
        };
        let arguments = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default();
        for index in indexes {
            if arguments
                .get(*index)
                .is_some_and(|argument| text(*argument, source) == "nil")
            {
                issues.push(node_issue(
                    "hoonarqube-go:SA1012",
                    "Pass context.TODO or context.Background instead of nil.",
                    arguments[*index],
                    source,
                ));
            }
        }
    });
}

fn check_native_archive_paths(
    root: Node<'_>,
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    let archive_types: HashSet<String> = [("archive/zip", "File"), ("archive/tar", "Header")]
        .into_iter()
        .filter_map(|(package, name)| imports.qualified(package, name))
        .collect();
    if archive_types.is_empty() {
        return;
    }
    let join_functions: HashSet<String> = ["path", "path/filepath"]
        .into_iter()
        .filter_map(|package| imports.qualified(package, "Join"))
        .collect();
    if join_functions.is_empty() {
        return;
    }

    walk(root, &mut |function| {
        if !is_function(function) {
            return;
        }
        let archive_entries = collect_archive_entries(function, source, imports, &archive_types);
        if archive_entries.is_empty() {
            return;
        }

        let mut archive_names = HashSet::<String>::new();
        walk(function, &mut |node| {
            if matches!(
                node.kind(),
                "short_var_declaration" | "assignment_statement"
            ) && let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) && let Some(name) = first_identifier(left, source)
                && selector_is_archive_name(right, source, &archive_entries)
            {
                archive_names.insert(name.to_string());
            }
        });

        walk(function, &mut |node| {
            if node.kind() != "call_expression"
                || !node
                    .child_by_field_name("function")
                    .is_some_and(|callee| join_functions.contains(text(callee, source)))
            {
                return;
            }
            let arguments = node
                .child_by_field_name("arguments")
                .map(named_children)
                .unwrap_or_default();
            let unsafe_argument = arguments.iter().find(|argument| {
                selector_is_archive_name(**argument, source, &archive_entries)
                    || (argument.kind() == "identifier"
                        && archive_names.contains(text(**argument, source)))
            });
            if let Some(argument) = unsafe_argument {
                issues.push(node_issue(
                    "hoonarqube-go:G305",
                    "Validate and contain this archive entry name before joining it to the extraction root.",
                    *argument,
                    source,
                ));
            }
        });
    });
}

fn collect_archive_entries(
    function: Node<'_>,
    source: &str,
    imports: &GoImports,
    archive_entry_types: &HashSet<String>,
) -> HashSet<String> {
    let archive_reader_types: HashSet<String> = [("archive/zip", "Reader")]
        .into_iter()
        .filter_map(|(package, name)| imports.qualified(package, name))
        .collect();
    let archive_reader_calls: HashSet<String> =
        [("archive/zip", "OpenReader"), ("archive/zip", "NewReader")]
            .into_iter()
            .filter_map(|(package, name)| imports.qualified(package, name))
            .collect();
    let mut entries = HashSet::new();
    let mut readers = HashSet::new();
    walk(function, &mut |node| {
        if node != function
            && ancestors(node)
                .take_while(|ancestor| *ancestor != function)
                .any(is_function)
        {
            return;
        }
        if node.kind() == "parameter_declaration"
            && let Some(kind) = node.child_by_field_name("type")
        {
            let declared_type = text(kind, source).trim_start_matches('*');
            let target = if archive_entry_types.contains(declared_type) {
                &mut entries
            } else if archive_reader_types.contains(declared_type) {
                &mut readers
            } else {
                return;
            };
            let mut cursor = node.walk();
            target.extend(
                node.children_by_field_name("name", &mut cursor)
                    .map(|name| text(name, source).to_string()),
            );
        }
        if matches!(
            node.kind(),
            "short_var_declaration" | "assignment_statement"
        ) && let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) && expression_calls_any(right, source, &archive_reader_calls)
            && let Some(name) = first_identifier(left, source)
        {
            readers.insert(name.to_string());
        }
    });
    walk(function, &mut |node| {
        if (node != function
            && ancestors(node)
                .take_while(|ancestor| *ancestor != function)
                .any(is_function))
            || node.kind() != "range_clause"
            || node.child_by_field_name("right").is_none_or(|right| {
                selector_parts(right, source).is_none_or(|(receiver, member)| {
                    member != "File" || !readers.contains(receiver)
                })
            })
        {
            return;
        }
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        if let Some(entry) = named_children(left)
            .into_iter()
            .rfind(|name| name.kind() == "identifier")
        {
            entries.insert(text(entry, source).to_string());
        }
    });
    entries
}

fn expression_calls_any(node: Node<'_>, source: &str, callees: &HashSet<String>) -> bool {
    let mut found = false;
    walk(node, &mut |candidate| {
        if candidate.kind() == "call_expression"
            && candidate
                .child_by_field_name("function")
                .is_some_and(|function| callees.contains(text(function, source)))
        {
            found = true;
        }
    });
    found
}

fn selector_is_archive_name(
    node: Node<'_>,
    source: &str,
    archive_entries: &HashSet<String>,
) -> bool {
    selector_parts(node, source)
        .is_some_and(|(receiver, member)| member == "Name" && archive_entries.contains(receiver))
}

fn check_native_composite(
    node: Node<'_>,
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    if imports
        .qualified("net/http", "Server")
        .is_some_and(|name| text(type_node, source) == name)
        && !literal_has_key(body, "ReadHeaderTimeout", source)
    {
        issues.push(node_issue(
            "hoonarqube-go:G112",
            "Set ReadHeaderTimeout on this http.Server.",
            type_node,
            source,
        ));
    }
    if imports
        .qualified("crypto/tls", "Config")
        .is_some_and(|name| text(type_node, source) == name)
        && literal_key_value(body, "InsecureSkipVerify", source) == Some("true")
    {
        let target = literal_key_node(body, "InsecureSkipVerify", source).unwrap_or(type_node);
        issues.push(node_issue(
            "hoonarqube-go:G402",
            "Do not disable TLS certificate verification.",
            target,
            source,
        ));
    }
    if imports
        .qualified("net/http", "Cookie")
        .is_some_and(|name| text(type_node, source) == name)
        && cookie_literal_is_keyed_or_empty(body)
        && cookie_literal_is_provably_insecure(node, body, source, imports)
    {
        issues.push(node_issue(
            "hoonarqube-go:G124",
            "Set Secure and HttpOnly, and use SameSite Lax or Strict on this HTTP cookie.",
            type_node,
            source,
        ));
    }
}

fn cookie_literal_is_keyed_or_empty(body: Node<'_>) -> bool {
    let elements = named_children(body);
    elements.is_empty()
        || elements
            .iter()
            .any(|element| element.kind() == "keyed_element")
}

fn cookie_literal_is_provably_insecure(
    literal: Node<'_>,
    body: Node<'_>,
    source: &str,
    imports: &GoImports,
) -> bool {
    let values = cookie_effective_security_values(literal, body, source);
    if matches!(values.secure, None | Some("false"))
        || matches!(values.http_only, None | Some("false"))
    {
        return true;
    }
    let Some(http) = imports.alias("net/http") else {
        return true;
    };
    let Some(same_site) = values.same_site else {
        return true;
    };
    let compact: String = same_site
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    matches!(compact.as_str(), "0" | "1" | "4")
        || compact == format!("{http}.SameSiteDefaultMode")
        || compact == format!("{http}.SameSiteNoneMode")
}

struct CookieSecurityValues<'source> {
    secure: Option<&'source str>,
    http_only: Option<&'source str>,
    same_site: Option<&'source str>,
}

fn cookie_effective_security_values<'source>(
    literal: Node<'_>,
    body: Node<'_>,
    source: &'source str,
) -> CookieSecurityValues<'source> {
    let mut values = CookieSecurityValues {
        secure: literal_key_value(body, "Secure", source),
        http_only: literal_key_value(body, "HttpOnly", source),
        same_site: literal_key_value(body, "SameSite", source),
    };
    let Some(binding) = cookie_literal_binding(literal, source) else {
        return values;
    };
    let Some(function) = ancestors(literal).find(|ancestor| is_function(*ancestor)) else {
        return values;
    };
    let Some(statement_list) =
        ancestors(literal).find(|ancestor| ancestor.kind() == "statement_list")
    else {
        return values;
    };
    walk(function, &mut |candidate| {
        if candidate.start_byte() <= literal.end_byte()
            || candidate.kind() != "assignment_statement"
            || ancestors(candidate).find(|ancestor| is_function(*ancestor)) != Some(function)
            || ancestors(candidate).find(|ancestor| ancestor.kind() == "statement_list")
                != Some(statement_list)
        {
            return;
        }
        let (Some(left), Some(right)) = (
            candidate.child_by_field_name("left"),
            candidate.child_by_field_name("right"),
        ) else {
            return;
        };
        let targets = expression_list_items(left);
        let assigned_values = expression_list_items(right);
        if targets.len() != assigned_values.len() {
            return;
        }
        for (target, assigned) in targets.into_iter().zip(assigned_values) {
            let Some((receiver, member)) = selector_parts(target, source) else {
                continue;
            };
            if receiver != binding {
                continue;
            }
            let assigned = Some(text(assigned, source));
            if member == "Secure" {
                values.secure = assigned;
            }
            if member == "HttpOnly" {
                values.http_only = assigned;
            }
            if member == "SameSite" {
                values.same_site = assigned;
            }
        }
    });
    values
}

fn cookie_literal_binding<'source>(
    literal: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    for owner in ancestors(literal) {
        if is_function(owner) {
            break;
        }
        if matches!(
            owner.kind(),
            "short_var_declaration" | "assignment_statement"
        ) && owner.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() <= literal.start_byte() && right.end_byte() >= literal.end_byte()
        }) {
            let targets = simple_assignment_targets(owner, source);
            if targets.len() == 1 {
                return Some(text(targets[0].1, source));
            }
        }
        if owner.kind() == "var_spec"
            && owner.child_by_field_name("value").is_some_and(|value| {
                value.start_byte() <= literal.start_byte() && value.end_byte() >= literal.end_byte()
            })
        {
            let mut cursor = owner.walk();
            let names: Vec<_> = owner.children_by_field_name("name", &mut cursor).collect();
            if names.len() == 1 {
                return Some(text(names[0], source));
            }
        }
    }
    None
}

fn expression_list_items(node: Node<'_>) -> Vec<Node<'_>> {
    if node.kind() == "expression_list" {
        named_children(node)
    } else {
        vec![node]
    }
}

fn check_native_serialized_secret(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let Some(tag) = node.child_by_field_name("tag") else {
        return;
    };
    let tag_text = text(tag, source);
    if !has_exposed_serialization_tag(tag_text) {
        return;
    }
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        let value = text(name, source);
        let normalized = value.to_ascii_lowercase().replace('_', "");
        if value.starts_with(char::is_uppercase)
            && [
                "password",
                "passwd",
                "passphrase",
                "secret",
                "token",
                "apikey",
                "privatekey",
            ]
            .iter()
            .any(|word| normalized.contains(word))
        {
            issues.push(node_issue(
                "hoonarqube-go:G117",
                "Remove the serialization tag or keep this secret field unexported.",
                name,
                source,
            ));
        }
    }
}

fn has_exposed_serialization_tag(tag: &str) -> bool {
    ["json", "yaml", "xml", "toml"].into_iter().any(|format| {
        let marker = format!("{format}:\"");
        let mut remaining = tag;
        while let Some(start) = remaining.find(&marker) {
            let value = &remaining[start + marker.len()..];
            let Some(end) = value.find('"') else {
                return false;
            };
            if value[..end].split(',').next() != Some("-") {
                return true;
            }
            remaining = &value[end + 1..];
        }
        false
    })
}

fn check_native_waitgroup_add(
    node: Node<'_>,
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    let Some(sync_alias) = imports.alias("sync") else {
        return;
    };
    let waitgroups = declared_waitgroups(node, source, sync_alias);
    if waitgroups.is_empty() {
        return;
    }
    walk(node, &mut |child| {
        if child.kind() != "call_expression" {
            return;
        }
        let Some(function) = child.child_by_field_name("function") else {
            return;
        };
        let Some((receiver, member)) = selector_parts(function, source) else {
            return;
        };
        if member == "Add" && waitgroups.contains(receiver) {
            issues.push(node_issue(
                "hoonarqube-go:SA2000",
                "Call WaitGroup.Add before starting the goroutine.",
                function,
                source,
            ));
        }
    });
}

fn declared_waitgroups(node: Node<'_>, source: &str, sync_alias: &str) -> HashSet<String> {
    let Some(function) = ancestors(node).find(|ancestor| is_function(*ancestor)) else {
        return HashSet::new();
    };
    let mut names = HashSet::new();
    walk(function, &mut |candidate| {
        if candidate.kind() == "var_spec"
            && candidate
                .child_by_field_name("type")
                .is_some_and(|kind| text(kind, source) == format!("{sync_alias}.WaitGroup"))
        {
            let mut cursor = candidate.walk();
            names.extend(
                candidate
                    .children_by_field_name("name", &mut cursor)
                    .map(|name| text(name, source).to_string()),
            );
        }
    });
    names
}

fn check_native_discarded_append(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let Some(call) = first_named(node).filter(|child| child.kind() == "call_expression") else {
        return;
    };
    if call
        .child_by_field_name("function")
        .is_some_and(|function| text(function, source) == "append")
    {
        issues.push(node_issue(
            "hoonarqube-go:SA4010",
            "Use the slice returned by append.",
            call,
            source,
        ));
    }
}

fn check_native_lock_sequence(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let statements: Vec<_> = named_children(node)
        .into_iter()
        .filter(|child| child.kind() != "comment")
        .collect();
    for pair in statements.windows(2) {
        let Some((first_receiver, first_method, _)) = statement_call(pair[0], source) else {
            continue;
        };
        if first_method != "Lock" {
            continue;
        }
        if let Some((second_receiver, "Unlock", call)) = statement_call(pair[1], source)
            && second_receiver == first_receiver
        {
            issues.push(node_issue(
                "hoonarqube-go:SA2001",
                "Remove this empty critical section or move protected work inside it.",
                call,
                source,
            ));
        }
        if pair[1].kind() == "defer_statement"
            && let Some((second_receiver, "Lock", call)) = statement_call(pair[1], source)
            && second_receiver == first_receiver
        {
            issues.push(node_issue(
                "hoonarqube-go:SA2003",
                "Defer Unlock instead of Lock.",
                call,
                source,
            ));
        }
    }
}

fn check_native_statement_flow(
    node: Node<'_>,
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    let statements: Vec<_> = named_children(node)
        .into_iter()
        .filter(|child| child.kind() != "comment")
        .collect();
    check_native_overwritten_values(&statements, source, issues);
    check_native_nil_map_assignments(&statements, source, issues);
    check_native_defer_before_error(&statements, source, imports, issues);
}

fn check_native_overwritten_values(statements: &[Node<'_>], source: &str, issues: &mut Vec<Issue>) {
    let mut unread = HashMap::<String, Node<'_>>::new();
    for statement in statements {
        if !is_native_assignment(*statement) {
            let mut reads = HashSet::new();
            collect_identifier_names(*statement, source, &mut reads);
            unread.retain(|name, _| !reads.contains(name));
            if statement_has_nested_block(*statement) {
                unread.clear();
            }
            continue;
        }
        let targets = simple_assignment_targets(*statement, source);
        if targets.is_empty() {
            unread.clear();
            continue;
        }
        let reads = native_assignment_reads(*statement, source);
        unread.retain(|name, _| !reads.contains(name));
        report_overwritten_targets(&mut unread, targets, source, issues);
    }
}

fn native_assignment_reads(node: Node<'_>, source: &str) -> HashSet<String> {
    let mut reads = HashSet::new();
    if let Some(right) = node.child_by_field_name("right") {
        collect_identifier_names(right, source, &mut reads);
    }
    if node.kind() == "assignment_statement"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| text(operator, source) != "=")
        && let Some(left) = node.child_by_field_name("left")
    {
        // Compound assignments read their target before writing it. Treating
        // `value += delta` as a plain overwrite incorrectly reports the value
        // that feeds the operation as unused.
        collect_identifier_names(left, source, &mut reads);
    }
    reads
}

fn report_overwritten_targets<'tree>(
    unread: &mut HashMap<String, Node<'tree>>,
    targets: Vec<(String, Node<'tree>)>,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for (name, target) in targets {
        if let Some(previous) = unread.insert(name, target) {
            issues.push(node_issue(
                "hoonarqube-go:SA4006",
                "Use this assigned value before overwriting it.",
                previous,
                source,
            ));
        }
    }
}

fn check_native_nil_map_assignments(
    statements: &[Node<'_>],
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let mut nil_maps = HashSet::<String>::new();
    for statement in statements {
        if matches!(statement.kind(), "declaration" | "var_declaration") {
            nil_maps.extend(nil_map_declarations(*statement, source));
            continue;
        }
        if is_native_assignment(*statement) {
            report_nil_map_writes(*statement, source, &nil_maps, issues);
            update_nil_map_facts(*statement, source, &mut nil_maps);
            continue;
        }
        if statement_has_nested_block(*statement) {
            nil_maps.clear();
        }
    }
}

fn is_native_assignment(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "short_var_declaration" | "assignment_statement"
    )
}

fn statement_has_nested_block(node: Node<'_>) -> bool {
    node.named_children(&mut node.walk())
        .any(|child| matches!(child.kind(), "block" | "statement_list"))
}

fn report_nil_map_writes(
    statement: Node<'_>,
    source: &str,
    nil_maps: &HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    issues.extend(
        nil_map_index_operands(statement, source, nil_maps)
            .into_iter()
            .map(|operand| {
                node_issue(
                    "hoonarqube-go:SA5000",
                    "Initialize this map before assigning an entry.",
                    operand,
                    source,
                )
            }),
    );
}

fn update_nil_map_facts(statement: Node<'_>, source: &str, nil_maps: &mut HashSet<String>) {
    let assigned_nil = nil_assignment_targets(statement, source);
    for (name, _) in simple_assignment_targets(statement, source) {
        if assigned_nil.contains(&name) {
            nil_maps.insert(name);
        } else {
            nil_maps.remove(&name);
        }
    }
}

fn nil_map_declarations(statement: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    walk(statement, &mut |candidate| {
        if candidate.kind() != "var_spec"
            || candidate
                .child_by_field_name("type")
                .is_none_or(|kind| kind.kind() != "map_type")
            || candidate
                .child_by_field_name("value")
                .is_some_and(|value| text(value, source).trim() != "nil")
        {
            return;
        }
        let mut cursor = candidate.walk();
        names.extend(
            candidate
                .children_by_field_name("name", &mut cursor)
                .map(|name| text(name, source).to_string()),
        );
    });
    names
}

fn nil_assignment_targets(node: Node<'_>, source: &str) -> HashSet<String> {
    if node.kind() != "assignment_statement" {
        return HashSet::new();
    }
    let targets = simple_assignment_targets(node, source);
    let Some(right) = node.child_by_field_name("right") else {
        return HashSet::new();
    };
    let values = if right.kind() == "expression_list" {
        named_children(right)
    } else {
        vec![right]
    };
    if targets.len() != values.len() {
        return HashSet::new();
    }
    targets
        .into_iter()
        .zip(values)
        .filter_map(|((name, _), value)| (text(value, source) == "nil").then_some(name))
        .collect()
}

fn nil_map_index_operands<'tree>(
    statement: Node<'tree>,
    source: &str,
    nil_maps: &HashSet<String>,
) -> Vec<Node<'tree>> {
    let Some(left) = statement.child_by_field_name("left") else {
        return Vec::new();
    };
    let mut indexed = Vec::new();
    walk(left, &mut |candidate| {
        if candidate.kind() == "index_expression"
            && let Some(operand) = candidate.child_by_field_name("operand")
            && operand.kind() == "identifier"
            && nil_maps.contains(text(operand, source))
        {
            indexed.push(operand);
        }
    });
    indexed
}

fn check_native_defer_before_error(
    statements: &[Node<'_>],
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    let Some(os) = imports.alias("os") else {
        return;
    };
    for window in statements.windows(3) {
        let assignment = window[0];
        if !matches!(
            assignment.kind(),
            "short_var_declaration" | "assignment_statement"
        ) {
            continue;
        }
        let targets = simple_assignment_targets(assignment, source);
        if targets.len() != 2 {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        let mut opening_call = None;
        walk(right, &mut |candidate| {
            if opening_call.is_none()
                && candidate.kind() == "call_expression"
                && candidate
                    .child_by_field_name("function")
                    .is_some_and(|function| {
                        ["Open", "OpenFile", "Create"]
                            .iter()
                            .any(|member| text(function, source) == format!("{os}.{member}"))
                    })
            {
                opening_call = Some(candidate);
            }
        });
        if opening_call.is_none() {
            continue;
        }
        let resource = &targets[0].0;
        let error = &targets[1].0;
        let Some((receiver, "Close", close)) = statement_call(window[1], source) else {
            continue;
        };
        if window[1].kind() == "defer_statement"
            && receiver == resource
            && window[2].kind() == "if_statement"
            && window[2]
                .child_by_field_name("condition")
                .is_some_and(|condition| {
                    let mut names = HashSet::new();
                    collect_identifier_names(condition, source, &mut names);
                    names.contains(error)
                })
        {
            issues.push(node_issue(
                "hoonarqube-go:SA5001",
                "Check the open error before deferring Close.",
                close,
                source,
            ));
        }
    }
}

fn simple_assignment_targets<'tree>(node: Node<'tree>, source: &str) -> Vec<(String, Node<'tree>)> {
    let Some(left) = node.child_by_field_name("left") else {
        return Vec::new();
    };
    let candidates = if left.kind() == "expression_list" {
        named_children(left)
    } else {
        vec![left]
    };
    candidates
        .into_iter()
        .filter(|target| target.kind() == "identifier" && text(*target, source) != "_")
        .map(|target| (text(target, source).to_string(), target))
        .collect()
}

fn collect_identifier_names(node: Node<'_>, source: &str, names: &mut HashSet<String>) {
    walk(node, &mut |candidate| {
        if candidate.kind() == "identifier" {
            names.insert(text(candidate, source).to_string());
        }
    });
}

fn check_native_loop(node: Node<'_>, source: &str, imports: &GoImports, issues: &mut Vec<Issue>) {
    check_native_loop_condition_update(node, source, issues);
    let endless = named_children(node)
        .into_iter()
        .all(|child| child.kind() == "block");
    if endless {
        walk(
            node.child_by_field_name("body").unwrap_or(node),
            &mut |child| {
                if child.kind() == "defer_statement"
                    && !ancestors(child)
                        .take_while(|ancestor| *ancestor != node)
                        .any(|ancestor| ancestor.kind() == "func_literal")
                {
                    issues.push(node_issue(
                        "hoonarqube-go:SA5003",
                        "Do not defer inside a loop that never returns.",
                        child,
                        source,
                    ));
                }
            },
        );
    }
    let Some(regexp) = imports.alias("regexp") else {
        return;
    };
    walk(
        node.child_by_field_name("body").unwrap_or(node),
        &mut |child| {
            if child.kind() != "call_expression" {
                return;
            }
            let Some(function) = child.child_by_field_name("function") else {
                return;
            };
            if ["Match", "MatchString", "Compile", "MustCompile"]
                .iter()
                .any(|member| text(function, source) == format!("{regexp}.{member}"))
                && child
                    .child_by_field_name("arguments")
                    .and_then(first_named)
                    .is_some_and(|argument| {
                        matches!(
                            argument.kind(),
                            "interpreted_string_literal" | "raw_string_literal"
                        )
                    })
            {
                issues.push(node_issue(
                    "hoonarqube-go:SA6000",
                    "Compile this constant regular expression before the loop.",
                    function,
                    source,
                ));
            }
        },
    );
}

fn check_native_loop_condition_update(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let Some(clause) = named_children(node)
        .into_iter()
        .find(|child| child.kind() == "for_clause")
    else {
        return;
    };
    let (Some(initializer), Some(condition), Some(update)) = (
        clause.child_by_field_name("initializer"),
        clause.child_by_field_name("condition"),
        clause.child_by_field_name("update"),
    ) else {
        return;
    };
    let initialized_names: HashSet<_> = simple_assignment_targets(initializer, source)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    if initialized_names.is_empty() {
        return;
    }
    let mut condition_names = HashSet::new();
    collect_identifier_names(condition, source, &mut condition_names);
    let mut update_names = HashSet::new();
    collect_identifier_names(update, source, &mut update_names);
    let mut body_names = HashSet::new();
    if let Some(body) = node.child_by_field_name("body") {
        walk(body, &mut |assignment| {
            if ancestors(assignment)
                .take_while(|ancestor| *ancestor != body)
                .any(is_function)
            {
                return;
            }
            match assignment.kind() {
                "short_var_declaration" | "assignment_statement" => {
                    body_names.extend(
                        simple_assignment_targets(assignment, source)
                            .into_iter()
                            .map(|(name, _)| name),
                    );
                }
                "inc_statement" | "dec_statement" => {
                    if let Some(target) = first_named(assignment)
                        && target.kind() == "identifier"
                    {
                        body_names.insert(text(target, source).to_string());
                    }
                }
                _ => {}
            }
        });
    }
    if let Some(variable) = initialized_names.into_iter().find(|variable| {
        condition_names.contains(variable)
            && !update_names.contains(variable)
            && !body_names.contains(variable)
    }) {
        issues.push(node_issue(
            "hoonarqube-go:SA4008",
            format!("Update {variable} because it controls this loop."),
            update,
            source,
        ));
    }
}

fn check_native_decompression_flows(
    root: Node<'_>,
    source: &str,
    imports: &GoImports,
    issues: &mut Vec<Issue>,
) {
    let Some(io_alias) = imports.alias("io") else {
        return;
    };
    let decompression_calls: HashSet<String> = [
        ("compress/bzip2", "NewReader"),
        ("compress/flate", "NewReader"),
        ("compress/gzip", "NewReader"),
        ("compress/lzw", "NewReader"),
        ("compress/zlib", "NewReader"),
    ]
    .into_iter()
    .filter_map(|(path, member)| imports.qualified(path, member))
    .collect();
    if decompression_calls.is_empty() {
        return;
    }

    walk(root, &mut |function| {
        if !is_function(function) {
            return;
        }
        let (spec, definitions) =
            collect_decompression_events(function, source, io_alias, &decompression_calls);
        report_decompression_events(spec, &definitions, source, issues);
    });
}

fn collect_decompression_events<'tree>(
    function: Node<'tree>,
    source: &str,
    io_alias: &str,
    decompression_calls: &HashSet<String>,
) -> (
    ControlFlowSpec<DecompressionEvent<'tree>>,
    HashMap<usize, Node<'tree>>,
) {
    let mut definitions = HashMap::new();
    let spec = function.child_by_field_name("body").map_or_else(
        || ControlFlowSpec::Seq(Vec::new()),
        |body| {
            decompression_control_flow(
                body,
                source,
                io_alias,
                decompression_calls,
                &mut definitions,
            )
        },
    );
    (spec, definitions)
}

fn decompression_control_flow<'tree>(
    node: Node<'tree>,
    source: &str,
    io_alias: &str,
    decompression_calls: &HashSet<String>,
    definitions: &mut HashMap<usize, Node<'tree>>,
) -> ControlFlowSpec<DecompressionEvent<'tree>> {
    match node.kind() {
        "block" | "statement_list" => ControlFlowSpec::Seq(
            named_children(node)
                .into_iter()
                .map(|child| {
                    decompression_control_flow(
                        child,
                        source,
                        io_alias,
                        decompression_calls,
                        definitions,
                    )
                })
                .collect(),
        ),
        "if_statement" => {
            decompression_if_flow(node, source, io_alias, decompression_calls, definitions)
        }
        "for_statement" => {
            decompression_for_flow(node, source, io_alias, decompression_calls, definitions)
        }
        "expression_switch_statement" | "type_switch_statement" | "select_statement" => {
            decompression_branch_flow(node, source, io_alias, decompression_calls, definitions)
        }
        "break_statement" => ControlFlowSpec::Break,
        "continue_statement" => ControlFlowSpec::Continue,
        "return_statement" => ControlFlowSpec::Seq(vec![
            decompression_leaf_flow(node, source, io_alias, decompression_calls, definitions),
            ControlFlowSpec::Return,
        ]),
        _ => decompression_leaf_flow(node, source, io_alias, decompression_calls, definitions),
    }
}

fn decompression_if_flow<'tree>(
    node: Node<'tree>,
    source: &str,
    io_alias: &str,
    decompression_calls: &HashSet<String>,
    definitions: &mut HashMap<usize, Node<'tree>>,
) -> ControlFlowSpec<DecompressionEvent<'tree>> {
    let mut sequence = Vec::new();
    if let Some(initializer) = node.child_by_field_name("initializer") {
        sequence.push(decompression_leaf_flow(
            initializer,
            source,
            io_alias,
            decompression_calls,
            definitions,
        ));
    }
    let then_arm = node.child_by_field_name("consequence").map_or_else(
        || ControlFlowSpec::Seq(Vec::new()),
        |branch| {
            decompression_control_flow(branch, source, io_alias, decompression_calls, definitions)
        },
    );
    let else_arm = node.child_by_field_name("alternative").map(|branch| {
        Box::new(decompression_control_flow(
            branch,
            source,
            io_alias,
            decompression_calls,
            definitions,
        ))
    });
    sequence.push(ControlFlowSpec::If {
        condition: DecompressionEvent::Nop,
        then_arm: Box::new(then_arm),
        else_arm,
    });
    ControlFlowSpec::Seq(sequence)
}

fn decompression_for_flow<'tree>(
    node: Node<'tree>,
    source: &str,
    io_alias: &str,
    decompression_calls: &HashSet<String>,
    definitions: &mut HashMap<usize, Node<'tree>>,
) -> ControlFlowSpec<DecompressionEvent<'tree>> {
    let clause = named_children(node)
        .into_iter()
        .find(|child| matches!(child.kind(), "for_clause" | "range_clause"));
    let init_node = clause.and_then(|clause| {
        clause
            .child_by_field_name("initializer")
            .or((clause.kind() == "range_clause").then_some(clause))
    });
    let step_node = clause.and_then(|clause| clause.child_by_field_name("update"));
    let init = init_node.map(|initializer| {
        Box::new(decompression_leaf_flow(
            initializer,
            source,
            io_alias,
            decompression_calls,
            definitions,
        ))
    });
    let step = step_node.map(|update| {
        Box::new(decompression_leaf_flow(
            update,
            source,
            io_alias,
            decompression_calls,
            definitions,
        ))
    });
    let body = node.child_by_field_name("body").map_or_else(
        || ControlFlowSpec::Seq(Vec::new()),
        |body| decompression_control_flow(body, source, io_alias, decompression_calls, definitions),
    );
    ControlFlowSpec::For {
        init,
        condition: Some(DecompressionEvent::Nop),
        body: Box::new(body),
        step,
    }
}

fn decompression_branch_flow<'tree>(
    node: Node<'tree>,
    source: &str,
    io_alias: &str,
    decompression_calls: &HashSet<String>,
    definitions: &mut HashMap<usize, Node<'tree>>,
) -> ControlFlowSpec<DecompressionEvent<'tree>> {
    let mut prefix = Vec::new();
    if let Some(initializer) = node.child_by_field_name("initializer") {
        prefix.push(decompression_leaf_flow(
            initializer,
            source,
            io_alias,
            decompression_calls,
            definitions,
        ));
    }
    let mut alternatives = Vec::new();
    let mut fallback = None;
    for case in named_children(node).into_iter().filter(|child| {
        matches!(
            child.kind(),
            "expression_case" | "type_case" | "communication_case" | "default_case"
        )
    }) {
        let body = named_children(case)
            .into_iter()
            .find(|child| child.kind() == "statement_list")
            .map_or_else(
                || ControlFlowSpec::Seq(Vec::new()),
                |body| {
                    decompression_control_flow(
                        body,
                        source,
                        io_alias,
                        decompression_calls,
                        definitions,
                    )
                },
            );
        if case.kind() == "default_case" {
            fallback = Some(Box::new(body));
        } else {
            alternatives.push(body);
        }
    }
    for alternative in alternatives.into_iter().rev() {
        fallback = Some(Box::new(ControlFlowSpec::If {
            condition: DecompressionEvent::Nop,
            then_arm: Box::new(alternative),
            else_arm: fallback,
        }));
    }
    prefix.push(fallback.map_or_else(|| ControlFlowSpec::Seq(Vec::new()), |flow| *flow));
    ControlFlowSpec::Seq(prefix)
}

fn decompression_leaf_flow<'tree>(
    node: Node<'tree>,
    source: &str,
    io_alias: &str,
    decompression_calls: &HashSet<String>,
    definitions: &mut HashMap<usize, Node<'tree>>,
) -> ControlFlowSpec<DecompressionEvent<'tree>> {
    let mut syntax_events = Vec::new();
    if matches!(
        node.kind(),
        "short_var_declaration" | "assignment_statement"
    ) {
        syntax_events.push((node.start_byte(), 0_u8, node));
    }
    walk(node, &mut |candidate| {
        if candidate.kind() != "call_expression"
            || ancestors(candidate)
                .take_while(|ancestor| *ancestor != node)
                .any(is_function)
        {
            return;
        }
        syntax_events.push((candidate.start_byte(), 1_u8, candidate));
    });
    syntax_events.sort_by_key(|event| (event.0, event.1));

    let mut events = Vec::new();
    for (_, kind, node) in syntax_events {
        if kind == 0 {
            let Some((event, defines_reader)) =
                decompression_assignment_event(node, source, decompression_calls)
            else {
                continue;
            };
            if defines_reader {
                definitions.insert(node.start_byte(), node);
            }
            events.push(event);
            continue;
        }
        let Some(call_function) = node.child_by_field_name("function") else {
            continue;
        };
        if text(call_function, source) != format!("{io_alias}.Copy") {
            continue;
        }
        let arguments = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default();
        if let Some(reader) = arguments
            .get(1)
            .filter(|reader| reader.kind() == "identifier")
        {
            events.push(DecompressionEvent::Copy {
                reader: text(*reader, source).to_string(),
                node: *reader,
            });
        }
    }
    ControlFlowSpec::Seq(events.into_iter().map(ControlFlowSpec::Stmt).collect())
}

fn decompression_assignment_event<'tree>(
    node: Node<'tree>,
    source: &str,
    decompression_calls: &HashSet<String>,
) -> Option<(DecompressionEvent<'tree>, bool)> {
    let name = first_identifier(node.child_by_field_name("left")?, source)?;
    let right = node.child_by_field_name("right")?;
    if decompression_calls
        .iter()
        .any(|call| text(right, source).contains(call))
    {
        return Some((
            DecompressionEvent::Define {
                name: name.to_string(),
                site: node.start_byte(),
            },
            true,
        ));
    }
    if let Some(source_name) = simple_identifier_expression(right, source) {
        return Some((
            DecompressionEvent::Propagate {
                source: source_name.to_string(),
                target: name.to_string(),
            },
            false,
        ));
    }
    Some((
        DecompressionEvent::Kill {
            name: name.to_string(),
        },
        false,
    ))
}

fn report_decompression_events(
    spec: ControlFlowSpec<DecompressionEvent<'_>>,
    definitions: &HashMap<usize, Node<'_>>,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let cfg = build_from_blocks(spec, DecompressionEvent::Nop, DecompressionEvent::Nop);
    let result = solve_dataflow(
        &cfg,
        Direction::Forward,
        &TaintFacts::<String, usize>::new(),
        TaintFacts::meet_union,
        |facts, event| {
            let mut next = facts.clone();
            match event {
                DecompressionEvent::Define { name, site } => {
                    next.clear(name);
                    next.taint(name.clone(), *site);
                }
                DecompressionEvent::Kill { name } => {
                    next.clear(name);
                }
                DecompressionEvent::Propagate { source, target } => {
                    next.propagate(source, target.clone());
                }
                DecompressionEvent::Nop | DecompressionEvent::Copy { .. } => {}
            }
            next
        },
        |_block, facts| facts.clone(),
    );
    for block in cfg.blocks() {
        let DecompressionEvent::Copy { reader, node } = cfg.payload(block) else {
            continue;
        };
        let mut issue = node_issue(
            "hoonarqube-go:G110",
            "Wrap this decompression reader with io.LimitReader before copying.",
            *node,
            source,
        );
        let mut has_origin = false;
        for site in result.in_fact(block).origins(reader) {
            let Some(definition) = definitions.get(site) else {
                continue;
            };
            has_origin = true;
            issue = issue.with_flow(vec![
                FlowLocation::in_primary_file(
                    "Decompression reader created here.",
                    node_range(*definition, source),
                ),
                FlowLocation::in_primary_file(
                    "Unbounded decompressed data reaches io.Copy here.",
                    node_range(*node, source),
                ),
            ]);
        }
        if has_origin {
            issues.push(issue);
        }
    }
}

#[derive(Debug)]
enum DecompressionEvent<'tree> {
    Nop,
    Define { name: String, site: usize },
    Kill { name: String },
    Propagate { source: String, target: String },
    Copy { reader: String, node: Node<'tree> },
}

fn simple_identifier_expression<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    if node.kind() == "identifier" {
        return Some(text(node, source));
    }
    if node.kind() == "expression_list" && node.named_child_count() == 1 {
        return node
            .named_child(0)
            .filter(|child| child.kind() == "identifier")
            .map(|child| text(child, source));
    }
    None
}

fn statement_call<'tree, 'source>(
    statement: Node<'tree>,
    source: &'source str,
) -> Option<(&'source str, &'source str, Node<'tree>)> {
    let mut call = None;
    walk(statement, &mut |node| {
        if call.is_none() && node.kind() == "call_expression" {
            call = Some(node);
        }
    });
    let call = call?;
    let function = call.child_by_field_name("function")?;
    let (receiver, method) = selector_parts(function, source)?;
    Some((receiver, method, call))
}

fn selector_parts<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<(&'source str, &'source str)> {
    if node.kind() != "selector_expression" {
        return None;
    }
    Some((
        text(node.child_by_field_name("operand")?, source),
        text(node.child_by_field_name("field")?, source),
    ))
}

fn literal_has_key(node: Node<'_>, key: &str, source: &str) -> bool {
    literal_key_node(node, key, source).is_some()
}

fn literal_key_node<'tree>(node: Node<'tree>, key: &str, source: &str) -> Option<Node<'tree>> {
    named_children(node).into_iter().find_map(|child| {
        (child.kind() == "keyed_element"
            && child
                .child_by_field_name("key")
                .is_some_and(|candidate| text(candidate, source) == key))
        .then(|| child.child_by_field_name("key"))
        .flatten()
    })
}

fn literal_key_value<'source>(
    node: Node<'_>,
    key: &str,
    source: &'source str,
) -> Option<&'source str> {
    named_children(node).into_iter().find_map(|child| {
        (child.kind() == "keyed_element"
            && child
                .child_by_field_name("key")
                .is_some_and(|candidate| text(candidate, source) == key))
        .then(|| {
            child
                .child_by_field_name("value")
                .map(|value| text(value, source))
        })
        .flatten()
    })
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn first_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() == "identifier" {
        return Some(text(node, source));
    }
    let mut found = None;
    walk(node, &mut |child| {
        if found.is_none() && child.kind() == "identifier" {
            found = Some(text(child, source));
        }
    });
    found
}

fn parse_go_integer(value: &str) -> Option<u32> {
    let value = value.replace('_', "");
    let (radix, digits) = if let Some(value) = value.strip_prefix("0o") {
        (8, value)
    } else if let Some(value) = value.strip_prefix("0O") {
        (8, value)
    } else if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (16, value)
    } else if let Some(value) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        (2, value)
    } else if value.starts_with('0') && value.len() > 1 {
        (8, &value[1..])
    } else {
        (10, value.as_str())
    };
    u32::from_str_radix(digits, radix).ok()
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
        let line_start = before.rfind('\n').map_or(0, |newline| newline + 1);
        Pos {
            line: u32_saturating(line),
            column: u32_saturating(source[line_start..offset].chars().count()),
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

#[derive(Debug)]
struct LineFacts {
    code: Vec<bool>,
    comments: Vec<bool>,
    imports: Vec<bool>,
}

impl LineFacts {
    fn collect(source: &str, root: Node<'_>) -> Self {
        let line_count = source.lines().count();
        let mut source_without_comments = source.as_bytes().to_vec();
        let mut comments = vec![false; line_count];
        let mut imports = vec![false; line_count];
        walk(root, &mut |node| match node.kind() {
            "comment" => {
                mark_rows(&mut comments, node);
                for byte in &mut source_without_comments[node.byte_range()] {
                    if !matches!(*byte, b'\n' | b'\r') {
                        *byte = b' ';
                    }
                }
            }
            "import_declaration" => mark_rows(&mut imports, node),
            _ => {}
        });
        let code = source_without_comments
            .split(|byte| *byte == b'\n')
            .take(line_count)
            .map(|line| line.iter().any(|byte| !byte.is_ascii_whitespace()))
            .collect();
        Self {
            code,
            comments,
            imports,
        }
    }

    fn code_lines_in(&self, node: Node<'_>) -> usize {
        let start = node.start_position().row.min(self.code.len());
        let end = (node.end_position().row + 1).min(self.code.len());
        self.code[start..end]
            .iter()
            .filter(|is_code| **is_code)
            .count()
    }
}

fn mark_rows(rows: &mut [bool], node: Node<'_>) {
    let start = node.start_position().row.min(rows.len());
    let end = (node.end_position().row + 1).min(rows.len());
    rows[start..end].fill(true);
}

fn check_lines(
    path: &std::path::Path,
    source: &str,
    line_facts: &LineFacts,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    for (index, line) in source.lines().enumerate() {
        let length = line.chars().count();
        if length > options.maximum_line_length
            && !line_facts.imports[index]
            && !(line_facts.comments[index]
                && !line_facts.code[index]
                && is_url_only_comment_line(line))
        {
            issues.push(line_issue(
                "go:S103",
                format!(
                    "Split this {0} characters long line (which is greater than {1} authorized).",
                    length, options.maximum_line_length
                ),
                index,
                0,
                length,
            ));
        }
    }
    let code_lines = line_facts.code.iter().filter(|is_code| **is_code).count();
    if code_lines > options.maximum_lines_of_code {
        issues.push(Issue::new(
            "go:S104",
            format!(
                "File \"{}\" has {code_lines} lines, which is greater than {} authorized. Split it into smaller files.",
                path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
                options.maximum_lines_of_code
            ),
            Range::file_level(),
        ));
    }
}

fn is_url_only_comment_line(line: &str) -> bool {
    let content = line
        .trim()
        .trim_start_matches(['/', '*'])
        .trim_end_matches(['/', '*'])
        .trim();
    let mut tokens = content.split_whitespace();
    tokens.next().is_some_and(is_url) && tokens.all(is_url)
}

fn is_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn check_header(source: &str, options: &AnalyzerOptions, issues: &mut Vec<Issue>) {
    if !options.header_format.is_empty() && !source.starts_with(&options.header_format) {
        issues.push(Issue::new(
            "go:S1451",
            "Add or update the header of this file.",
            Range::file_level(),
        ));
    }
}

fn check_textual(source: &str, root: Node<'_>, issues: &mut Vec<Issue>) {
    check_comment_tags(root, source, issues);
    let code = code_only_source(source, root);
    let header_semicolons = control_header_semicolons(root);
    for (line_index, (line, original)) in code.lines().zip(source.lines()).enumerate() {
        check_mistyped_assignments(line_index, line, original, issues);
        check_statement_separator(
            line_index,
            line,
            original,
            header_semicolons
                .get(&line_index)
                .map_or(&[], Vec::as_slice),
            issues,
        );
    }
    check_empty_block_comments(root, source, issues);
}

fn check_comment_tags(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        if node.kind() != "comment" {
            return;
        }
        let comment = text(node, source);
        for (tag, key, message) in [
            (
                "FIXME",
                "go:S1134",
                "Take the required action to fix the issue indicated by this \"FIXME\" comment.",
            ),
            (
                "TODO",
                "go:S1135",
                "Complete the task associated to this TODO comment.",
            ),
        ] {
            issues.extend(comment.match_indices(tag).map(|(relative, _)| {
                relative_issue(key, message, node, source, relative, relative + tag.len())
            }));
        }
    });
}

fn check_mistyped_assignments(
    line_index: usize,
    line: &str,
    original: &str,
    issues: &mut Vec<Issue>,
) {
    for token in ["=+", "=-"] {
        let mut start = 0;
        while let Some(relative) = line[start..].find(token) {
            let column = start + relative;
            let message = if token == "=+" {
                "Was \"+=\" meant instead?"
            } else {
                "Was \"-=\" meant instead?"
            };
            let (start_column, end_column) = character_columns(original, column, column + 2);
            issues.push(line_issue(
                "go:S2757",
                message,
                line_index,
                start_column,
                end_column,
            ));
            start = column + 2;
        }
    }
}

fn check_statement_separator(
    line_index: usize,
    line: &str,
    original: &str,
    ignored_columns: &[usize],
    issues: &mut Vec<Issue>,
) {
    if let Some(column) = statement_separator(line, ignored_columns) {
        let (start, end) = statement_after(line, column);
        let (start_column, end_column) = character_columns(original, start, end);
        issues.push(line_issue(
            "go:S122",
            "Reformat the code to have only one statement per line.",
            line_index,
            start_column,
            end_column,
        ));
    }
}

fn control_header_semicolons(root: Node<'_>) -> HashMap<usize, Vec<usize>> {
    let mut semicolons: HashMap<usize, Vec<usize>> = HashMap::new();
    walk_all(root, &mut |node| {
        if node.kind() == ";"
            && node.parent().is_some_and(|parent| {
                matches!(parent.kind(), "for_clause" | "type_switch_statement")
            })
        {
            semicolons
                .entry(node.start_position().row)
                .or_default()
                .push(node.start_position().column);
        }
    });
    semicolons
}

fn check_empty_block_comments(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        if node.kind() == "comment"
            && let comment = text(node, source)
            && comment.starts_with("/*")
            && comment.ends_with("*/")
            && comment[2..comment.len() - 2].trim().is_empty()
        {
            issues.push(node_issue(
                "go:S4663",
                "Remove this comment, it is empty.",
                node,
                source,
            ));
        }
    });
}

fn code_only_source(source: &str, root: Node<'_>) -> String {
    let mut code = source.as_bytes().to_vec();
    walk(root, &mut |node| {
        if matches!(
            node.kind(),
            "comment" | "interpreted_string_literal" | "raw_string_literal" | "rune_literal"
        ) {
            for byte in &mut code[node.byte_range()] {
                if !matches!(*byte, b'\n' | b'\r') {
                    *byte = b' ';
                }
            }
        }
    });
    String::from_utf8(code).expect("masked Go source remains valid UTF-8")
}

fn character_columns(line: &str, start: usize, end: usize) -> (usize, usize) {
    (line[..start].chars().count(), line[..end].chars().count())
}

fn check_syntax_errors(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let mut cursor = root.walk();
    if let Some(node) = root
        .named_children(&mut cursor)
        .find(|node| !is_top_level_declaration(*node))
    {
        issues.push(syntax_issue(node, source));
        return;
    }
    walk(root, &mut |node| {
        if node.is_error() {
            issues.push(syntax_issue(node, source));
        }
    });
    if issues.is_empty() {
        walk_all(root, &mut |node| {
            if node.is_missing() {
                issues.push(node_issue(
                    "go:S2260",
                    "A parsing error occurred in this file.",
                    node,
                    source,
                ));
            }
        });
    }
}

fn syntax_issue(node: Node<'_>, source: &str) -> Issue {
    let row = node.start_position().row;
    let end = source
        .lines()
        .nth(row)
        .map_or(0, |line| line.trim_end().chars().count());
    line_issue(
        "go:S2260",
        "A parsing error occurred in this file.",
        row,
        0,
        end,
    )
}

fn is_top_level_declaration(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "comment"
            | "package_clause"
            | "import_declaration"
            | "const_declaration"
            | "var_declaration"
            | "type_declaration"
            | "function_declaration"
            | "method_declaration"
    )
}

fn check_node(
    node: Node<'_>,
    source: &str,
    line_facts: &LineFacts,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    match node.kind() {
        "function_declaration" | "method_declaration" | "func_literal" => {
            check_function(node, source, line_facts, options, issues);
        }
        "block" => check_block(node, source, issues),
        "statement_list" => check_statements(node, source, issues),
        "parenthesized_expression" => {
            if first_named(node).is_some_and(|child| child.kind() == "parenthesized_expression") {
                issues.push(keyword_issue(
                    "go:S1110",
                    "Remove these useless parentheses.",
                    node,
                    1,
                    1,
                    source,
                ));
            }
        }
        "binary_expression" => check_binary(node, source, options, issues),
        "unary_expression" => check_unary(node, source, issues),
        "if_statement" => check_if(node, source, issues),
        "expression_switch_statement" => check_switch(node, source, options, issues),
        "type_switch_statement" => {
            check_switch(node, source, options, issues);
            check_type_switch_alias(node, source, issues);
        }
        "assignment_statement" => check_assignment(node, source, issues),
        "short_var_declaration" => {
            check_assignment(node, source, issues);
            check_variable_declaration(node, source, issues);
        }
        "var_spec" => check_variable_declaration(node, source, issues),
        "range_clause" | "receive_statement" if has_direct_child(node, ":=") => {
            check_variable_declaration(node, source, issues);
        }
        "int_literal" => {
            let value = text(node, source);
            if value.len() > 1
                && value.starts_with('0')
                && value.bytes().all(|byte| byte.is_ascii_digit())
            {
                issues.push(node_issue(
                    "go:S1314",
                    "Use decimal values instead of octal ones.",
                    node,
                    source,
                ));
            }
        }
        _ => {}
    }

    if matches!(
        node.kind(),
        "if_statement" | "for_statement" | "expression_switch_statement" | "type_switch_statement"
    ) {
        let depth = control_depth(node);
        if depth == options.maximum_nesting_depth.saturating_add(1) {
            issues.push(keyword_issue(
                "go:S134",
                format!(
                    "Refactor this code to not nest more than {} control flow statements.",
                    options.maximum_nesting_depth
                ),
                node,
                0,
                if node.kind() == "for_statement" { 3 } else { 2 },
                source,
            ));
        }
    }
    if matches!(
        node.kind(),
        "expression_switch_statement" | "type_switch_statement"
    ) && ancestors(node)
        .take_while(|ancestor| !is_function(*ancestor))
        .any(is_switch)
    {
        issues.push(keyword_issue(
            "go:S1821",
            "Refactor the code to eliminate this nested \"switch\".",
            node,
            0,
            6,
            source,
        ));
    }
}

fn check_function(
    node: Node<'_>,
    source: &str,
    line_facts: &LineFacts,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    if let Some(name) = node.child_by_field_name("name") {
        let value = text(name, source);
        if !is_valid_name(value) {
            issues.push(node_issue(
                "go:S100",
                format!(
                    "Rename function \"{value}\" to match the regular expression ^(_|[a-zA-Z0-9]+)$"
                ),
                name,
                source,
            ));
        }
    }
    if let Some(parameters) = node.child_by_field_name("parameters") {
        let count = parameter_count(parameters);
        if count > options.maximum_function_parameters {
            issues.push(node_issue(
                "go:S107",
                format!(
                    "This function has {count} parameters, which is greater than the {0} authorized.",
                    options.maximum_function_parameters
                ),
                node.child_by_field_name("name").unwrap_or(parameters),
                source,
            ));
        }
        check_parameter_names(parameters, source, issues);
    }
    for field in ["receiver", "result"] {
        if let Some(parameters) = node
            .child_by_field_name(field)
            .filter(|child| child.kind() == "parameter_list")
        {
            check_parameter_names(parameters, source, issues);
        }
    }
    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    if !descendants(body).any(|child| !matches!(child.kind(), "statement_list" | "block")) {
        issues.push(node_issue("go:S1186", "Add a nested comment explaining why this function is empty or complete the implementation.", body, source));
    }
    let lines = line_facts.code_lines_in(node);
    if lines > options.maximum_function_lines {
        issues.push(node_issue(
            "go:S138",
            format!("This function has {lines} lines of code, which is greater than the {0} authorized. Split it into smaller functions.", options.maximum_function_lines),
            node.child_by_field_name("name").unwrap_or(node),
            source,
        ));
    }
    let cognitive = cognitive_complexity(body, source);
    if cognitive > options.maximum_cognitive_complexity {
        issues.push(node_issue(
            "go:S3776",
            format!("Refactor this method to reduce its Cognitive Complexity from {cognitive} to the {0} allowed.", options.maximum_cognitive_complexity),
            node.child_by_field_name("name").unwrap_or(node),
            source,
        ));
    }
}

fn check_parameter_names(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(node, &mut |child| {
        if child.kind() == "parameter_declaration" {
            let mut cursor = child.walk();
            for name in child
                .named_children(&mut cursor)
                .filter(|part| part.kind() == "identifier")
            {
                check_parameter_name(name, source, issues);
            }
        }
    });
}

fn check_block(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    if node.named_child_count() == 0
        && node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "if_statement" | "for_statement" | "expression_case" | "default_case"
            )
        })
    {
        issues.push(node_issue(
            "go:S108",
            "Either remove or fill this block of code.",
            node,
            source,
        ));
    }
}

fn check_variable_declaration(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    if node.kind() == "var_spec" {
        if !ancestors(node).any(is_function) {
            return;
        }
        let mut cursor = node.walk();
        for name in node.children_by_field_name("name", &mut cursor) {
            check_local_name(name, source, issues);
        }
        return;
    }
    if let Some(left) = node.child_by_field_name("left") {
        let mut cursor = left.walk();
        for name in left
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
        {
            check_local_name(name, source, issues);
        }
    }
}

fn check_type_switch_alias(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    if let Some(alias) = node.child_by_field_name("alias") {
        check_declared_names(alias, source, issues);
    }
}

fn check_declared_names(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let mut cursor = node.walk();
    for name in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier")
    {
        check_local_name(name, source, issues);
    }
}

fn check_statements(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let mut terminal: Option<Node<'_>> = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "comment" {
            continue;
        }
        if let Some(statement) = terminal {
            issues.push(node_issue(
                "go:S1763",
                format!(
                    "Refactor this piece of code to not have any dead code after this \"{}\".",
                    statement.kind().trim_end_matches("_statement")
                ),
                statement,
                source,
            ));
            break;
        }
        if matches!(
            child.kind(),
            "return_statement" | "break_statement" | "continue_statement" | "goto_statement"
        ) {
            terminal = Some(child);
        }
    }
}

fn check_unary(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    if node
        .child_by_field_name("operator")
        .is_some_and(|operator| text(operator, source) == "!")
        && let Some(mut operand) = node.child_by_field_name("operand")
    {
        while operand.kind() == "parenthesized_expression" {
            let Some(inner) = first_named(operand) else {
                return;
            };
            operand = inner;
        }
        if operand.kind() == "binary_expression"
            && let Some(operator) = operand.child_by_field_name("operator")
            && let Some(opposite) = opposite_comparison(text(operator, source))
        {
            issues.push(node_issue(
                "go:S1940",
                format!("Use the opposite operator (\"{opposite}\") instead."),
                node,
                source,
            ));
        }
    }
}

fn opposite_comparison(value: &str) -> Option<&'static str> {
    [
        ("==", "!="),
        ("!=", "=="),
        ("<=", ">"),
        (">=", "<"),
        ("<", ">="),
        (">", "<="),
    ]
    .into_iter()
    .find_map(|(operator, opposite)| (value == operator).then_some(opposite))
}

fn is_valid_name(value: &str) -> bool {
    value == "_" || (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

fn check_local_name(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let value = text(node, source);
    if !is_valid_name(value) {
        issues.push(node_issue(
            "go:S117",
            "Rename this local variable to match the regular expression \"^(_|[a-zA-Z0-9]+)$\".",
            node,
            source,
        ));
    }
}

fn check_parameter_name(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let value = text(node, source);
    if !is_valid_name(value) {
        issues.push(node_issue(
            "go:S117",
            "Rename this parameter to match the regular expression \"^(_|[a-zA-Z0-9]+)$\".",
            node,
            source,
        ));
    }
}

fn check_binary(node: Node<'_>, source: &str, options: &AnalyzerOptions, issues: &mut Vec<Issue>) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let operator = operator_text(node, source);
    check_identical_operands(left, right, source, issues);
    check_boolean_literal(left, right, operator, source, issues);
    check_logical_complexity(node, operator, source, options, issues);
    check_opposite_boolean_operator(node, right, operator, source, issues);
}

fn check_identical_operands(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if canonical_code(left, source) == canonical_code(right, source) {
        issues.push(node_issue(
            "go:S1764",
            "Correct one of the identical sub-expressions on both sides of this operator.",
            right,
            source,
        ));
    }
}

fn check_boolean_literal(
    left: Node<'_>,
    right: Node<'_>,
    operator: &str,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if (matches!(text(right, source), "true" | "false")
        || matches!(text(left, source), "true" | "false"))
        && matches!(operator, "&&" | "||" | "==" | "!=")
    {
        let literal = if matches!(text(left, source), "true" | "false") {
            left
        } else {
            right
        };
        issues.push(node_issue(
            "go:S1125",
            "Remove the unnecessary Boolean literal.",
            literal,
            source,
        ));
    }
}

fn check_logical_complexity(
    node: Node<'_>,
    operator: &str,
    source: &str,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    let count = logical_operator_count(node, source);
    if is_logical_operator(operator)
        && logical_parent(node, source).is_none()
        && count > options.maximum_expression_complexity
    {
        issues.push(node_issue(
            "go:S1067",
            format!("Reduce the number of conditional operators ({count}) used in the expression (maximum allowed {}).", options.maximum_expression_complexity),
            node,
            source,
        ));
    }
}

fn check_opposite_boolean_operator(
    node: Node<'_>,
    right: Node<'_>,
    operator: &str,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if matches!(
        (operator, text(right, source)),
        ("==", "false") | ("!=", "true")
    ) {
        issues.push(node_issue(
            "go:S1940",
            "Use the opposite operator instead.",
            node,
            source,
        ));
    }
}

fn check_if(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    if let Some(condition) = node.child_by_field_name("condition")
        && matches!(text(condition, source), "true" | "false")
    {
        issues.push(node_issue(
            "go:S1145",
            "Remove this useless \"if\" statement.",
            condition,
            source,
        ));
    }
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "if_statement")
    {
        return;
    }
    let (condition_count, branches, last_if, ends_with_else) =
        collect_if_chain(node, source, issues);
    report_if_chain_smells(
        node,
        condition_count,
        &branches,
        last_if,
        ends_with_else,
        source,
        issues,
    );
}

fn collect_if_chain<'tree>(
    node: Node<'tree>,
    source: &str,
    issues: &mut Vec<Issue>,
) -> (usize, Vec<(String, Node<'tree>)>, Node<'tree>, bool) {
    let mut conditions: Vec<(String, u32)> = Vec::new();
    let mut branches = Vec::new();
    let mut current = Some(node);
    let mut last_if = node;
    let mut ends_with_else = false;
    while let Some(item) = current {
        last_if = item;
        if let Some(condition) = item.child_by_field_name("condition") {
            let value = canonical_code(condition, source);
            if let Some((_, line)) = conditions.iter().find(|(previous, _)| previous == &value) {
                issues.push(node_issue(
                    "go:S1862",
                    format!("This condition duplicates the one on line {line}."),
                    condition,
                    source,
                ));
            }
            conditions.push((value, u32_saturating(condition.start_position().row + 1)));
        }
        if let Some(consequence) = item.child_by_field_name("consequence") {
            branches.push((canonical_code(consequence, source), consequence));
        }
        match item.child_by_field_name("alternative") {
            Some(alternative) if alternative.kind() == "if_statement" => {
                current = Some(alternative);
            }
            Some(alternative) => {
                branches.push((canonical_code(alternative, source), alternative));
                ends_with_else = true;
                current = None;
            }
            None => current = None,
        }
    }
    (conditions.len(), branches, last_if, ends_with_else)
}

fn report_if_chain_smells(
    node: Node<'_>,
    condition_count: usize,
    branches: &[(String, Node<'_>)],
    last_if: Node<'_>,
    ends_with_else: bool,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if condition_count > 1 && !ends_with_else {
        let start = last_if.start_position();
        let start_column = point_column(start, last_if.start_byte(), source);
        let offset = start_column.saturating_sub(5);
        issues.push(line_issue(
            "go:S126",
            "Add the missing \"else\" clause.",
            start.row,
            offset,
            offset + 7,
        ));
    }
    if branches.len() >= 3
        && let Some((original, duplicate)) = duplicate_branch(branches)
    {
        issues.push(node_issue(
            "go:S1871",
            format!(
                "This branch's code block is the same as the block for the branch on line {}.",
                original.start_position().row + 1
            ),
            duplicate,
            source,
        ));
    }
    if ends_with_else
        && branches.len() > 1
        && branches.iter().all(|branch| branch.0 == branches[0].0)
    {
        issues.push(node_issue("go:S3923", "Remove this conditional structure or edit its code blocks so that they're not all the same.", node, source));
    }
}

fn check_switch(node: Node<'_>, source: &str, options: &AnalyzerOptions, issues: &mut Vec<Issue>) {
    let mut cases = Vec::new();
    for child in descendants(node).filter(|child| switch_owner(*child) == Some(node)) {
        if matches!(child.kind(), "expression_case" | "type_case") {
            cases.push(child);
            let lines = child
                .end_position()
                .row
                .saturating_sub(child.start_position().row);
            if lines > options.maximum_case_lines {
                issues.push(header_issue(
                    "go:S1151",
                    format!(
                        "Reduce this case clause number of lines from {lines} to at most {}, for example by extracting code into methods.",
                        options.maximum_case_lines
                    ),
                    child,
                    source,
                ));
            }
        }
    }
    let has_default = descendants(node)
        .any(|child| child.kind() == "default_case" && switch_owner(child) == Some(node));
    if !has_default {
        issues.push(keyword_issue(
            "go:S131",
            "Add a default clause to this \"switch\" statement.",
            node,
            0,
            6,
            source,
        ));
    }
    let branch_count = cases.len() + usize::from(has_default);
    if branch_count > options.maximum_switch_cases {
        issues.push(keyword_issue(
            "go:S1479",
            format!(
                "Reduce the number of switch branches from {branch_count} to at most {}.",
                options.maximum_switch_cases
            ),
            node,
            0,
            6,
            source,
        ));
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
        && canonical_code(left, source) == canonical_code(right, source)
    {
        issues.push(node_issue(
            "go:S1656",
            "Remove or correct this useless self-assignment.",
            node,
            source,
        ));
    }
}

fn check_duplicate_strings(
    root: Node<'_>,
    source: &str,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    let mut values: HashMap<String, Vec<Node<'_>>> = HashMap::new();
    walk(root, &mut |node| {
        if matches!(
            node.kind(),
            "interpreted_string_literal" | "raw_string_literal"
        ) && !is_excluded_duplicate_string(node, source)
        {
            let value = text(node, source).to_string();
            values.entry(value).or_default().push(node);
        }
    });
    let threshold = options.duplicate_string_threshold.max(2);
    for nodes in values.values().filter(|nodes| nodes.len() >= threshold) {
        let node = nodes[0];
        let literal = text(node, source);
        issues.push(node_issue(
            "go:S1192",
            format!(
                "Define a constant instead of duplicating this literal {literal} {} times.",
                nodes.len()
            ),
            node,
            source,
        ));
    }
}

fn is_excluded_duplicate_string(node: Node<'_>, source: &str) -> bool {
    let literal = text(node, source);
    let value = match node.kind() {
        "interpreted_string_literal" => literal
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(literal),
        "raw_string_literal" => literal
            .strip_prefix('`')
            .and_then(|value| value.strip_suffix('`'))
            .unwrap_or(literal),
        _ => literal,
    };
    literal_character_count(node.kind(), value) <= 5
        || value
            .chars()
            .all(|character| character.is_alphanumeric() || character == '_')
        || is_logging_or_error_argument(node, source)
}

fn literal_character_count(kind: &str, value: &str) -> usize {
    if kind != "interpreted_string_literal" {
        return value.chars().count();
    }
    let mut count = 0;
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        count += 1;
        if character != '\\' {
            continue;
        }
        match characters.next() {
            Some('x') => consume(&mut characters, 2),
            Some('u') => consume(&mut characters, 4),
            Some('U') => consume(&mut characters, 8),
            Some(character) if character.is_digit(8) => consume(&mut characters, 2),
            Some(_) | None => {}
        }
    }
    count
}

fn consume(characters: &mut impl Iterator<Item = char>, count: usize) {
    for _ in 0..count {
        if characters.next().is_none() {
            break;
        }
    }
}

fn is_logging_or_error_argument(node: Node<'_>, source: &str) -> bool {
    let Some(arguments) = node
        .parent()
        .filter(|parent| parent.kind() == "argument_list")
    else {
        return false;
    };
    let Some(call) = arguments
        .parent()
        .filter(|parent| parent.kind() == "call_expression")
    else {
        return false;
    };
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let function = compact_code(function, source);
    let Some((receiver, method)) = function.rsplit_once('.') else {
        return false;
    };
    matches!(
        (receiver, method),
        ("fmt", "Errorf") | ("errors" | "xerrors", "New")
    ) || matches!(
        method,
        "Debug"
            | "Debugf"
            | "Error"
            | "Errorf"
            | "Fatal"
            | "Fatalf"
            | "Fatalln"
            | "Info"
            | "Infof"
            | "Log"
            | "Panic"
            | "Panicf"
            | "Panicln"
            | "Print"
            | "Printf"
            | "Println"
            | "Warn"
            | "Warnf"
    )
}

fn check_duplicate_functions(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let mut bodies: HashMap<String, Node<'_>> = HashMap::new();
    walk(root, &mut |node| {
        if matches!(node.kind(), "function_declaration" | "method_declaration")
            && let Some(body) = node.child_by_field_name("body")
        {
            if !descendants(body)
                .any(|child| !matches!(child.kind(), "statement_list" | "block" | "comment"))
            {
                return;
            }
            let value = canonical_code(body, source);
            if let Some(original) = bodies.get(&value).copied() {
                let original_name = original
                    .child_by_field_name("name")
                    .map_or("function", |name| text(name, source));
                let duplicate_name = node.child_by_field_name("name").unwrap_or(node);
                issues.push(node_issue(
                    "go:S4144",
                    format!(
                        "Update this function so that its implementation is not identical to \"{original_name}\" on line {}.",
                        original.start_position().row + 1
                    ),
                    duplicate_name,
                    source,
                ));
            } else {
                bodies.insert(value, node);
            }
        }
    });
}

fn metrics(source: &str, line_facts: &LineFacts) -> FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        source.lines().count()
    };
    FileMetrics {
        lines: u32_saturating(lines),
        code_lines: u32_saturating(line_facts.code.iter().filter(|value| **value).count()),
        comment_lines: u32_saturating(line_facts.comments.iter().filter(|value| **value).count()),
    }
}

fn statement_separator(line: &str, ignored_columns: &[usize]) -> Option<usize> {
    let bytes = line.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        if byte != b';' || ignored_columns.contains(&index) {
            continue;
        }
        let tail = line[index + 1..].trim_start();
        if !tail.is_empty()
            && !tail.starts_with('}')
            && !tail.starts_with("case ")
            && !tail.starts_with("default:")
        {
            return Some(index);
        }
    }
    None
}

fn statement_after(line: &str, separator: usize) -> (usize, usize) {
    let tail = &line[separator + 1..];
    let leading = tail.len().saturating_sub(tail.trim_start().len());
    let start = separator + 1 + leading;
    let candidate = &line[start..];
    let mut block_depth = 0_usize;
    let mut raw_end = line.len();
    for (relative, character) in candidate.char_indices() {
        match character {
            '{' => block_depth += 1,
            '}' | ';' if block_depth == 0 => {
                raw_end = start + relative;
                break;
            }
            '}' => block_depth -= 1,
            _ => {}
        }
    }
    let end = raw_end.saturating_sub(line[..raw_end].len() - line[..raw_end].trim_end().len());
    (start, end)
}

fn parameter_count(node: Node<'_>) -> usize {
    let mut count = 0;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            let mut inner = child.walk();
            let names = child
                .named_children(&mut inner)
                .filter(|part| part.kind() == "identifier")
                .count();
            count += names.max(1);
        }
    }
    count
}

fn cognitive_complexity(node: Node<'_>, source: &str) -> usize {
    let mut total = 0;
    let mut pending = vec![(node, 0_usize)];
    while let Some((current, nesting)) = pending.pop() {
        if current != node && current.kind() == "func_literal" {
            continue;
        }
        let control = matches!(
            current.kind(),
            "if_statement"
                | "for_statement"
                | "expression_switch_statement"
                | "type_switch_statement"
                | "select_statement"
        );
        let else_if = current.kind() == "if_statement" && is_else_if(current);
        total += usize::from(control) * if else_if { 1 } else { nesting + 1 };
        if current.kind() == "if_statement"
            && current
                .child_by_field_name("alternative")
                .is_some_and(|alternative| alternative.kind() != "if_statement")
        {
            total += 1;
        }
        if current.kind() == "binary_expression"
            && is_logical_operator(operator_text(current, source))
            && logical_parent(current, source).is_none()
        {
            total += logical_sequence_count(current, source);
        }
        let next = nesting + usize::from(control && !else_if);
        push_named_children(&mut pending, current, next);
    }
    total
}

fn control_depth(node: Node<'_>) -> usize {
    let mut depth = 1;
    let mut current = node;
    while let Some(parent) = current.parent() {
        if is_function(parent) {
            break;
        }
        if is_control(parent) && !(current.kind() == "if_statement" && is_else_if(current)) {
            depth += 1;
        }
        current = parent;
    }
    depth
}

fn logical_operator_count(node: Node<'_>, source: &str) -> usize {
    logical_operators(node, source).0
}

fn logical_sequence_count(node: Node<'_>, source: &str) -> usize {
    logical_operators(node, source).1
}

enum LogicalItem<'tree> {
    Node(Node<'tree>),
    Operator(Node<'tree>),
}

fn logical_operators(node: Node<'_>, source: &str) -> (usize, usize) {
    let mut count = 0;
    let mut sequences = 0;
    let mut previous = "";
    let mut pending = vec![LogicalItem::Node(node)];
    while let Some(item) = pending.pop() {
        match item {
            LogicalItem::Operator(binary) => {
                record_logical_operator(binary, source, &mut count, &mut sequences, &mut previous);
            }
            LogicalItem::Node(current) => enqueue_logical_children(node, current, &mut pending),
        }
    }
    (count, sequences)
}

fn record_logical_operator<'source>(
    binary: Node<'_>,
    source: &'source str,
    count: &mut usize,
    sequences: &mut usize,
    previous: &mut &'source str,
) {
    let operator = operator_text(binary, source);
    if !is_logical_operator(operator) {
        return;
    }
    *count += 1;
    if operator != *previous {
        *sequences += 1;
        *previous = operator;
    }
}

fn enqueue_logical_children<'tree>(
    root: Node<'tree>,
    current: Node<'tree>,
    pending: &mut Vec<LogicalItem<'tree>>,
) {
    if current != root && current.kind() == "func_literal" {
        return;
    }
    if let Some((left, right)) = binary_operands(current) {
        pending.push(LogicalItem::Node(right));
        pending.push(LogicalItem::Operator(current));
        pending.push(LogicalItem::Node(left));
        return;
    }
    for index in (0..current.named_child_count()).rev() {
        if let Some(child) = current.named_child(index) {
            pending.push(LogicalItem::Node(child));
        }
    }
}

fn binary_operands(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "binary_expression")
        .then(|| {
            node.child_by_field_name("left")
                .zip(node.child_by_field_name("right"))
        })
        .flatten()
}

fn logical_parent<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "parenthesized_expression" {
            current = parent;
            continue;
        }
        return (parent.kind() == "binary_expression"
            && is_logical_operator(operator_text(parent, source)))
        .then_some(parent);
    }
    None
}

fn operator_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.child_by_field_name("operator")
        .map_or("", |operator| text(operator, source))
}

fn is_logical_operator(operator: &str) -> bool {
    matches!(operator, "&&" | "||")
}

fn is_control(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "if_statement" | "for_statement" | "expression_switch_statement" | "type_switch_statement"
    )
}

fn is_switch(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "expression_switch_statement" | "type_switch_statement"
    )
}

fn is_function(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn is_else_if(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "if_statement" && parent.child_by_field_name("alternative") == Some(node)
    })
}

fn switch_owner(node: Node<'_>) -> Option<Node<'_>> {
    ancestors(node)
        .take_while(|ancestor| !is_function(*ancestor))
        .find(|ancestor| is_switch(*ancestor))
}

fn has_direct_child(node: Node<'_>, kind: &str) -> bool {
    (0..node.child_count()).any(|index| node.child(index).is_some_and(|child| child.kind() == kind))
}

fn canonical_code(node: Node<'_>, source: &str) -> String {
    let mut value = String::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "comment" {
            continue;
        }
        if current.child_count() == 0 {
            value.push_str(current.kind());
            value.push('\0');
            value.push_str(text(current, source));
            value.push('\0');
        } else {
            for index in (0..current.child_count()).rev() {
                if let Some(child) = current.child(index) {
                    pending.push(child);
                }
            }
        }
    }
    value
}

fn compact_code(node: Node<'_>, source: &str) -> String {
    let mut value = String::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "comment" {
            continue;
        }
        if current.child_count() == 0 {
            value.push_str(text(current, source));
        } else {
            for index in (0..current.child_count()).rev() {
                if let Some(child) = current.child(index) {
                    pending.push(child);
                }
            }
        }
    }
    value
}

fn duplicate_branch<'tree>(
    branches: &[(String, Node<'tree>)],
) -> Option<(Node<'tree>, Node<'tree>)> {
    for (index, (value, original)) in branches.iter().enumerate() {
        if let Some((_, duplicate)) = branches[index + 1..]
            .iter()
            .find(|(candidate, _)| candidate == value)
        {
            return Some((*original, *duplicate));
        }
    }
    None
}

fn first_named(node: Node<'_>) -> Option<Node<'_>> {
    node.named_child(0)
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

struct Descendants<'tree> {
    pending: Vec<Node<'tree>>,
}

impl<'tree> Iterator for Descendants<'tree> {
    type Item = Node<'tree>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.pending.pop()?;
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                self.pending.push(child);
            }
        }
        Some(current)
    }
}

fn descendants(node: Node<'_>) -> Descendants<'_> {
    let mut pending = Vec::with_capacity(node.named_child_count());
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            pending.push(child);
        }
    }
    Descendants { pending }
}

fn push_named_children<'tree>(
    pending: &mut Vec<(Node<'tree>, usize)>,
    node: Node<'tree>,
    nesting: usize,
) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            pending.push((child, nesting));
        }
    }
}

fn ancestors(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    std::iter::successors(node.parent(), tree_sitter::Node::parent)
}

fn node_issue(key: &str, message: impl Into<String>, node: Node<'_>, source: &str) -> Issue {
    Issue::new(key, message, node_range(node, source))
}

fn keyword_issue(
    key: &str,
    message: impl Into<String>,
    node: Node<'_>,
    offset: usize,
    length: usize,
    source: &str,
) -> Issue {
    let point = node.start_position();
    let start_column = point_column(point, node.start_byte(), source);
    line_issue(
        key,
        message,
        point.row,
        start_column + offset,
        start_column + offset + length,
    )
}

fn header_issue(key: &str, message: impl Into<String>, node: Node<'_>, source: &str) -> Issue {
    let point = node.start_position();
    let start_column = point_column(point, node.start_byte(), source);
    let first_line = text(node, source).lines().next().unwrap_or_default();
    let length = first_line
        .find(':')
        .map_or(4, |column| first_line[..=column].chars().count());
    line_issue(key, message, point.row, start_column, start_column + length)
}

fn node_range(node: Node<'_>, source: &str) -> Range {
    Range {
        start: point_pos(node.start_position(), node.start_byte(), source),
        end: point_pos(node.end_position(), node.end_byte(), source),
    }
}

fn point_pos(point: Point, byte_offset: usize, source: &str) -> Pos {
    let column = point_column(point, byte_offset, source);
    Pos {
        line: u32_saturating(point.row + 1),
        column: u32_saturating(column),
    }
}

fn point_column(point: Point, byte_offset: usize, source: &str) -> usize {
    let row_start = byte_offset - point.column;
    source[row_start..byte_offset].chars().count()
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

fn relative_issue(
    key: &str,
    message: impl Into<String>,
    node: Node<'_>,
    source: &str,
    start: usize,
    end: usize,
) -> Issue {
    let value = text(node, source);
    let base = point_column(node.start_position(), node.start_byte(), source);
    let position = |offset: usize| {
        let before = &value[..offset];
        let line_offset = before.bytes().filter(|byte| *byte == b'\n').count();
        let column = before.rsplit_once('\n').map_or_else(
            || base + before.chars().count(),
            |(_, tail)| tail.chars().count(),
        );
        Pos {
            line: u32_saturating(node.start_position().row + line_offset + 1),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const TEST_RULE_KEYS: &[&str] = &[
        "go:S100", "go:S103", "go:S104", "go:S1067", "go:S107", "go:S108", "go:S1110", "go:S1125",
        "go:S1134", "go:S1135", "go:S1145", "go:S1151", "go:S117", "go:S1186", "go:S1192",
        "go:S122", "go:S126", "go:S131", "go:S1314", "go:S134", "go:S138", "go:S1451", "go:S1479",
        "go:S1656", "go:S1763", "go:S1764", "go:S1821", "go:S1862", "go:S1871", "go:S1940",
        "go:S2260", "go:S2757", "go:S3776", "go:S3923", "go:S4144", "go:S4663",
    ];

    fn keys(source: &str) -> Vec<String> {
        analyze(
            PathBuf::from("fixture.go"),
            source,
            &AnalyzerOptions::default(),
        )
        .issues
        .into_iter()
        .map(|issue| issue.rule_key)
        .collect()
    }

    fn keys_with_options(source: &str, options: &AnalyzerOptions) -> Vec<String> {
        analyze(PathBuf::from("fixture.go"), source, options)
            .issues
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect()
    }

    #[test]
    fn every_catalog_rule_has_production_and_test_contract() {
        assert_eq!(RULE_KEYS, TEST_RULE_KEYS);
        assert_eq!(RULE_KEYS.len(), 36);
    }

    #[test]
    fn structural_rules_emit_and_clean_control_stays_clean() {
        let bad = "package p\nfunc bad_name(a,b,c,d,e,f,g,h int) {}\nfunc f(x bool) bool {\n if true {\n  x = x\n  return x\n  x = false\n }\n return x == false\n}\n";
        let found = keys(bad);
        for key in [
            "go:S100", "go:S107", "go:S1186", "go:S1145", "go:S1656", "go:S1763", "go:S1125",
            "go:S1940",
        ] {
            assert!(found.iter().any(|actual| actual == key), "{key}: {found:?}");
        }
        assert!(keys("package p\nfunc good(value bool) bool { return !value }\n").is_empty());
    }

    #[test]
    fn textual_rules_distinguish_code_comments_and_literals() {
        let source = concat!(
            "package p\n",
            "const example = `TODO =+ ; /* */`\n",
            "func f() { value := 1; value =+ 2 }\n",
            "// FIXME real task\n",
            "/**/\n",
        );
        let found = keys(source);
        let count = |key: &str| found.iter().filter(|actual| actual.as_str() == key).count();
        assert_eq!(count("go:S1135"), 0, "TODO inside a string: {found:?}");
        assert_eq!(count("go:S1134"), 1, "real comment tag: {found:?}");
        assert_eq!(count("go:S2757"), 1, "real mistyped assignment: {found:?}");
        assert_eq!(count("go:S122"), 1, "real statement separator: {found:?}");
        assert_eq!(count("go:S4663"), 1, "real empty block comment: {found:?}");
    }

    #[test]
    fn reported_columns_count_unicode_characters_not_bytes() {
        let source = "package p\nfunc f() { café := 1; café = café } // café TODO\n";
        let report = analyze(
            PathBuf::from("fixture.go"),
            source,
            &AnalyzerOptions::default(),
        );
        for (key, anchor) in [("go:S1656", "café = café"), ("go:S1135", "TODO")] {
            let issue = report
                .issues
                .iter()
                .find(|issue| issue.rule_key == key)
                .unwrap_or_else(|| panic!("missing {key} finding: {:?}", report.issues));
            let line = source.lines().nth(1).expect("second line");
            let expected = line
                .split(anchor)
                .next()
                .expect("anchor prefix")
                .chars()
                .count();
            assert_eq!(issue.range.start.column, u32_saturating(expected), "{key}");
        }
    }

    #[test]
    fn nested_blocks_report_each_local_name_once() {
        let found = keys(concat!(
            "package p\n",
            "func f() {\n",
            " {\n",
            "  {\n",
            "   bad_name, other_bad := 1, 2\n",
            "   _, _ = bad_name, other_bad\n",
            "  }\n",
            " }\n",
            "}\n",
        ));
        assert_eq!(
            found.iter().filter(|key| key.as_str() == "go:S117").count(),
            2,
            "each declared name must fire once despite ancestor blocks: {found:?}"
        );
    }

    #[test]
    fn parser_errors_are_reported_without_panicking() {
        let fixture = keys("package p\nfunc broken( {");
        assert_eq!(
            fixture
                .iter()
                .filter(|key| key.as_str() == "go:S2260")
                .count(),
            1,
            "canonical oracle error must not duplicate: {fixture:?}"
        );
        for source in [
            "package p\nfunc missing() {\n",
            "package p\nfunc nested() { if true { println(1) }\n",
        ] {
            let found = keys(source);
            assert!(
                found.iter().any(|key| key == "go:S2260"),
                "missing-token parse failure was lost: {found:?}"
            );
        }
    }

    #[test]
    fn line_rules_and_metrics_use_syntax_aware_comment_boundaries() {
        let source = concat!(
            "package p\n",
            "var marker = \"/* not a comment */\"\n",
            "var raw = `first\n",
            "/* still string data */\n",
            "last`\n",
            "var mixed = 1 /* comment\n",
            "continued */ + 2\n",
            "/* pure\n",
            "comment */\n",
        );
        let report = analyze(
            PathBuf::from("fixture.go"),
            source,
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.metrics.lines, 9);
        assert_eq!(report.metrics.code_lines, 7);
        assert_eq!(report.metrics.comment_lines, 4);

        let long_source = concat!(
            "package p\n",
            "import \"example.com/an/import/path/that/is/intentionally/very/long\"\n",
            "// https://example.com/a/path/that/is/intentionally/very/long\n",
            "var value = \"this ordinary code line is intentionally too long\"\n",
        );
        let options = AnalyzerOptions {
            maximum_line_length: 40,
            ..AnalyzerOptions::default()
        };
        assert_eq!(
            keys_with_options(long_source, &options)
                .iter()
                .filter(|key| key.as_str() == "go:S103")
                .count(),
            1,
            "imports and URL-only comments are documented S103 exceptions"
        );
    }

    #[test]
    fn local_name_rule_respects_scope_and_all_declaration_forms() {
        let source = concat!(
            "package p\n",
            "var package_bad = 1\n",
            "type item struct{}\n",
            "func (receiver_bad item) method() (result_bad int) { return 1 }\n",
            "func f(ch <-chan int, value any, values []int) {\n",
            " for range_bad := range values { _ = range_bad }\n",
            " select { case receive_bad := <-ch: _ = receive_bad; default: }\n",
            " switch type_bad := value.(type) { default: _ = type_bad }\n",
            " _ = func(literal_bad int) { /* intentionally empty */ }\n",
            "}\n",
        );
        let found = keys(source);
        assert_eq!(
            found.iter().filter(|key| key.as_str() == "go:S117").count(),
            6,
            "receivers, named results, range, receive, type-switch, and literal parameters are local; package globals are not: {found:?}"
        );
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "go:S1186")
                .count(),
            0,
            "inline body comments explain intentionally empty function literals: {found:?}"
        );
    }

    #[test]
    fn name_rules_require_ascii_identifiers_and_allow_underscore_controls() {
        let found = keys(concat!(
            "package p\n",
            "func caféName(naïve int) {\n",
            " café := naïve\n",
            " _ = café\n",
            "}\n",
        ));
        assert_eq!(
            found.iter().filter(|key| key.as_str() == "go:S100").count(),
            1,
            "Unicode function names must not bypass S100: {found:?}"
        );
        assert_eq!(
            found.iter().filter(|key| key.as_str() == "go:S117").count(),
            2,
            "Unicode parameter and local names must fire S117: {found:?}"
        );

        let clean = keys(concat!(
            "package p\n",
            "func goodName(_ int, value2 int) {\n",
            " local3 := value2\n",
            " _ = local3\n",
            "}\n",
        ));
        assert!(
            clean.is_empty(),
            "ASCII alphanumeric and underscore controls must stay clean: {clean:?}"
        );
    }

    #[test]
    fn native_weak_crypto_rules_detect_dot_imports_but_ignore_blank_imports() {
        for (path, key) in [
            ("crypto/md5", "hoonarqube-go:G401"),
            ("crypto/sha1", "hoonarqube-go:G401"),
            ("crypto/des", "hoonarqube-go:G405"),
            ("crypto/rc4", "hoonarqube-go:G405"),
            ("golang.org/x/crypto/md4", "hoonarqube-go:G406"),
            ("golang.org/x/crypto/ripemd160", "hoonarqube-go:G406"),
        ] {
            let source = format!("package p\nimport . \"{path}\"\n");
            let found = native_keys(&source);
            assert_eq!(
                found.iter().filter(|found| found.as_str() == key).count(),
                1,
                "dot import {path} must emit {key}: {found:?}"
            );
        }

        for path in [
            "crypto/md5",
            "crypto/sha1",
            "crypto/des",
            "crypto/rc4",
            "golang.org/x/crypto/md4",
            "golang.org/x/crypto/ripemd160",
        ] {
            let source = format!("package p\nimport _ \"{path}\"\n");
            let found = native_keys(&source);
            assert!(
                found.is_empty(),
                "blank import {path} must stay clean: {found:?}"
            );
        }
    }

    #[test]
    fn nested_switches_own_only_their_direct_cases() {
        let source = concat!(
            "package p\n",
            "func f(x, y int) {\n",
            " switch x {\n",
            " case 0: switch y { case 0: println(y); default: println(x) }\n",
            " default: println(x)\n",
            " }\n",
            "}\n",
        );
        let options = AnalyzerOptions {
            maximum_switch_cases: 2,
            ..AnalyzerOptions::default()
        };
        let found = keys_with_options(source, &options);
        assert!(
            !found.iter().any(|key| key == "go:S1479"),
            "outer switch must not absorb nested switch cases: {found:?}"
        );
    }

    #[test]
    fn nesting_reports_only_first_exceeded_level_and_flattens_else_if() {
        let source = concat!(
            "package p\n",
            "func f(a, b, c, d bool) {\n",
            " if a { if b { if c { if d { println(d) } } } }\n",
            " if a { println(a) } else if b { println(b) } else if c { println(c) } else { println(d) }\n",
            "}\n",
        );
        let options = AnalyzerOptions {
            maximum_nesting_depth: 1,
            ..AnalyzerOptions::default()
        };
        let found = keys_with_options(source, &options);
        assert_eq!(
            found.iter().filter(|key| key.as_str() == "go:S134").count(),
            1,
            "deeper descendants and else-if clauses must not duplicate S134: {found:?}"
        );
    }

    #[test]
    fn canonical_comparisons_preserve_literal_content() {
        let source = concat!(
            "package p\n",
            "func left(ok bool) bool { if ok { println(\"a b\") } else { println(\"ab\") }; return \"a b\" == \"ab\" }\n",
            "func right(ok bool) bool { if ok { println(\"ab\") } else { println(\"a b\") }; return \"ab\" == \"a b\" }\n",
            "func tokens(ok bool) { if ok { go run() } else { gorun() } }\n",
        );
        let found = keys(source);
        for key in ["go:S1764", "go:S1871", "go:S3923", "go:S4144"] {
            assert!(
                !found.iter().any(|actual| actual == key),
                "whitespace inside literals is semantic for {key}: {found:?}"
            );
        }
    }

    #[test]
    fn duplicate_strings_honor_documented_exclusions_and_safe_threshold() {
        let source = concat!(
            "package p\n",
            "func f() {\n",
            " use(\"short\"); use(\"short\"); use(\"short\")\n",
            " use(\"\\u0061\"); use(\"\\u0061\"); use(\"\\u0061\")\n",
            " use(\"Letters123_\"); use(\"Letters123_\"); use(\"Letters123_\")\n",
            " log.Println(\"a duplicated logging message\"); log.Println(\"a duplicated logging message\"); log.Println(\"a duplicated logging message\")\n",
            " errors.New(\"a duplicated error message\"); errors.New(\"a duplicated error message\"); errors.New(\"a duplicated error message\")\n",
            " use(\"must be a constant!\"); use(\"must be a constant!\")\n",
            "}\n",
        );
        let options = AnalyzerOptions {
            duplicate_string_threshold: 0,
            ..AnalyzerOptions::default()
        };
        let found = keys_with_options(source, &options);
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "go:S1192")
                .count(),
            1,
            "zero is clamped to two occurrences; documented exclusions stay clean: {found:?}"
        );
    }

    #[test]
    fn logical_and_unary_rules_emit_once_for_the_owned_expression() {
        let source = concat!(
            "package p\n",
            "func f(a, b, c bool) bool {\n",
            " _ = a && b && c\n",
            " _ = !(a == b && c)\n",
            " return !(a == b)\n",
            "}\n",
        );
        let options = AnalyzerOptions {
            maximum_expression_complexity: 1,
            ..AnalyzerOptions::default()
        };
        let found = keys_with_options(source, &options);
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "go:S1067")
                .count(),
            1,
            "nested binary nodes belong to one logical expression: {found:?}"
        );
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "go:S1940")
                .count(),
            1,
            "only a directly negated comparison has a safe opposite operator: {found:?}"
        );
    }

    #[test]
    fn for_header_semicolons_do_not_hide_body_statement_separator() {
        let found = keys(concat!(
            "package p\n",
            "func f() { for i := 0; i < 1; i++ { println(i); println(i) } }\n",
        ));
        assert_eq!(
            found.iter().filter(|key| key.as_str() == "go:S122").count(),
            1,
            "only body separator should fire: {found:?}"
        );
        let clean = keys(concat!(
            "package p\n",
            "func f() { for i := 0; i < 1; i++ { println(i); } }\n",
        ));
        assert!(
            !clean.iter().any(|key| key == "go:S122"),
            "for headers and trailing semicolons are not multiple statements: {clean:?}"
        );
    }

    #[test]
    fn function_literal_complexity_does_not_leak_into_outer_function() {
        let source = concat!(
            "package p\n",
            "func outer() {\n",
            " _ = func(a, b bool) { if a { if b { println(b) } } }\n",
            "}\n",
        );
        let options = AnalyzerOptions {
            maximum_cognitive_complexity: 0,
            ..AnalyzerOptions::default()
        };
        let found = keys_with_options(source, &options);
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "go:S3776")
                .count(),
            1,
            "only function literal owns its nested control flow: {found:?}"
        );
    }

    #[test]
    fn deeply_nested_blocks_are_walked_iteratively() {
        let depth = 2_000;
        let source = format!(
            "package p\nfunc f() {{ {} value := 1; _ = value {} }}\n",
            "{".repeat(depth),
            "}".repeat(depth)
        );
        let options = AnalyzerOptions {
            maximum_function_lines: usize::MAX,
            ..AnalyzerOptions::default()
        };
        assert!(
            !keys_with_options(&source, &options)
                .iter()
                .any(|key| key == "go:S2260")
        );
    }

    fn native_keys(source: &str) -> Vec<String> {
        super::analyze_native(source)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect()
    }

    #[test]
    fn native_gosec_rules_require_resolved_standard_imports() {
        let found = native_keys(concat!(
            "package p\n",
            "import (\n",
            "  h \"net/http\"\n",
            "  \"crypto/tls\"\n",
            "  \"crypto/rsa\"\n",
            "  \"crypto/md5\"\n",
            "  \"crypto/sha1\"\n",
            "  \"os\"\n",
            ")\n",
            "var _ = h.Server{}\n",
            "var _ = h.Server{Handler: struct{ ReadHeaderTimeout int }{ReadHeaderTimeout: 1}}\n",
            "var _ = tls.Config{InsecureSkipVerify: true}\n",
            "func f() {\n",
            "  h.ListenAndServe(\":80\", nil)\n",
            "  os.MkdirAll(\"x\", 0777)\n",
            "  os.Chmod(\"x\", 0644)\n",
            "  os.WriteFile(\"x\", nil, 0666)\n",
            "  rsa.GenerateKey(nil, 1024)\n",
            "}\n",
        ));
        for key in [
            "hoonarqube-go:G112",
            "hoonarqube-go:G114",
            "hoonarqube-go:G301",
            "hoonarqube-go:G302",
            "hoonarqube-go:G306",
            "hoonarqube-go:G402",
            "hoonarqube-go:G403",
            "hoonarqube-go:G401",
        ] {
            assert!(
                found.iter().any(|found| found == key),
                "missing {key}: {found:?}"
            );
        }

        let clean = native_keys(concat!(
            "package p\n",
            "import (\"net/http\"; \"crypto/tls\"; \"crypto/rsa\"; \"os\")\n",
            "var _ = http.Server{ReadHeaderTimeout: 1}\n",
            "var _ = tls.Config{}\n",
            "var _ = tls.Config{RootCAs: struct{ InsecureSkipVerify bool }{InsecureSkipVerify: true}}\n",
            "func f() { os.MkdirAll(\"x\", 0750); os.Chmod(\"x\", 0600); os.WriteFile(\"x\", nil, 0600); rsa.GenerateKey(nil, 2048) }\n",
        ));
        assert!(clean.is_empty(), "unexpected native findings: {clean:?}");
    }

    #[test]
    fn native_cookie_and_sleep_rules_require_exact_standard_apis() {
        let found = native_keys(concat!(
            "package p\n",
            "import (h \"net/http\"; clock \"time\")\n",
            "var missing = h.Cookie{Name: \"session\"}\n",
            "var weak = h.Cookie{Secure: true, HttpOnly: true, SameSite: h.SameSiteDefaultMode}\n",
            "var crossSite = h.Cookie{Secure: true, HttpOnly: true, SameSite: h.SameSiteNoneMode}\n",
            "var numericNone = h.Cookie{Secure: true, HttpOnly: true, SameSite: 4}\n",
            "var nested = h.Cookie{Raw: struct{ Secure bool }{Secure: true}}\n",
            "func conditional(ready bool) {\n",
            "  cookie := &h.Cookie{Name: \"session\"}\n",
            "  if ready {\n",
            "    cookie.Secure = true\n",
            "    cookie.HttpOnly = true\n",
            "    cookie.SameSite = h.SameSiteLaxMode\n",
            "  }\n",
            "}\n",
            "func pause() { clock.Sleep(100) }\n",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-go:G124")
                .count(),
            6,
        );
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-go:SA1004")
                .count(),
            1,
        );

        let clean = native_keys(concat!(
            "package p\n",
            "import (h \"net/http\"; clock \"time\")\n",
            "var cookie = h.Cookie{Secure: true, HttpOnly: true, SameSite: h.SameSiteStrictMode}\n",
            "var configured = h.Cookie{Secure: secure, HttpOnly: httpOnly, SameSite: sameSite}\n",
            "var positional = h.Cookie{\"name\", \"value\"}\n",
            "const delay = 10\n",
            "func configure() {\n",
            "  cookie := &h.Cookie{Name: \"session\"}\n",
            "  cookie.Secure = true\n",
            "  cookie.HttpOnly = true\n",
            "  cookie.SameSite = h.SameSiteLaxMode\n",
            "}\n",
            "func pause() { clock.Sleep(0); clock.Sleep(121); clock.Sleep(delay); clock.Sleep(2 * clock.Nanosecond) }\n",
        ));
        assert!(clean.is_empty(), "unexpected native findings: {clean:?}");

        let custom = native_keys(concat!(
            "package p\n",
            "type Cookie struct { Secure bool }\n",
            "type clockType struct{}\n",
            "func (clockType) Sleep(int) {}\n",
            "var clock clockType\n",
            "var _ = Cookie{}\n",
            "func pause() { clock.Sleep(10) }\n",
        ));
        assert!(custom.is_empty(), "custom APIs must stay clean: {custom:?}");
    }

    #[test]
    fn native_go_flow_and_concurrency_rules_are_precise_on_owned_shapes() {
        let found = native_keys(concat!(
            "package p\n",
            "import (\"compress/gzip\"; \"io\"; \"regexp\"; \"sync\")\n",
            "func f(src io.Reader, dst io.Writer) {\n",
            "  var wg sync.WaitGroup\n",
            "  go func() { wg.Add(1) }()\n",
            "  mu.Lock(); mu.Unlock()\n",
            "  lock.Lock(); defer lock.Lock()\n",
            "  append([]int{}, 1)\n",
            "  for { defer close(done); regexp.MatchString(\"x\", \"x\") }\n",
            "  reader, _ := gzip.NewReader(src)\n",
            "  alias := reader\n",
            "  io.Copy(dst, alias)\n",
            "}\n",
        ));
        for key in [
            "hoonarqube-go:G110",
            "hoonarqube-go:SA2000",
            "hoonarqube-go:SA2001",
            "hoonarqube-go:SA2003",
            "hoonarqube-go:SA4010",
            "hoonarqube-go:SA5003",
            "hoonarqube-go:SA6000",
        ] {
            assert!(
                found.iter().any(|found| found == key),
                "missing {key}: {found:?}"
            );
        }

        let mutually_exclusive = native_keys(concat!(
            "package p\n",
            "import (\"compress/gzip\"; \"io\")\n",
            "func cleanDirect(src io.Reader, dst io.Writer, cond bool) {\n",
            "  var reader io.Reader\n",
            "  if cond { reader, _ = gzip.NewReader(src) } else { io.Copy(dst, reader) }\n",
            "}\n",
            "func cleanPropagation(src io.Reader, dst io.Writer, cond bool) {\n",
            "  var reader io.Reader\n",
            "  var alias io.Reader\n",
            "  if cond { reader, _ = gzip.NewReader(src) } else { alias = reader }\n",
            "  io.Copy(dst, alias)\n",
            "}\n",
            "func cleanReturn(src io.Reader, dst io.Writer, cond bool) {\n",
            "  var reader io.Reader\n",
            "  if cond { reader, _ = gzip.NewReader(src); return }\n",
            "  io.Copy(dst, reader)\n",
            "}\n",
        ));
        assert!(
            !mutually_exclusive
                .iter()
                .any(|key| key == "hoonarqube-go:G110"),
            "mutually exclusive taint steps must stay clean: {mutually_exclusive:?}",
        );

        let branch_to_join = native_keys(concat!(
            "package p\n",
            "import (\"compress/gzip\"; \"io\")\n",
            "func bad(src io.Reader, dst io.Writer, other io.Reader, cond bool) {\n",
            "  var reader io.Reader\n",
            "  if cond { reader, _ = gzip.NewReader(src) } else { reader = other }\n",
            "  io.Copy(dst, reader)\n",
            "}\n",
        ));
        assert!(
            branch_to_join.iter().any(|key| key == "hoonarqube-go:G110"),
            "taint from one feasible branch must reach the join: {branch_to_join:?}",
        );
    }

    #[test]
    fn native_go_unicode_and_serialized_secret_rules_report_exact_source() {
        let found = native_keys(concat!(
            "package p\n",
            "// suspicious \u{202e} marker\n",
            "type Config struct { APIToken string `json:\"api_token\"` }\n",
        ));
        assert!(found.iter().any(|key| key == "hoonarqube-go:G116"));
        assert!(found.iter().any(|key| key == "hoonarqube-go:G117"));

        let mixed_tags = native_keys(concat!(
            "package p\n",
            "type Config struct { Password string `json:\"-\" yaml:\"password\"` }\n",
        ));
        assert!(
            mixed_tags.iter().any(|key| key == "hoonarqube-go:G117"),
            "one ignored format must not hide another exposed format: {mixed_tags:?}",
        );
    }

    #[test]
    fn native_current_gosec_filesystem_and_crypto_rules_fire() {
        let found = native_keys(concat!(
            "package p\n",
            "import (\"archive/zip\"; \"crypto/des\"; \"crypto/md5\"; \"golang.org/x/crypto/md4\"; \"os\"; \"path/filepath\")\n",
            "var _ = des.BlockSize; var _ = md5.Size; var _ = md4.Size\n",
            "func extract(file *zip.File, root string) {\n",
            "  _ = filepath.Join(root, file.Name)\n",
            "  os.WriteFile(\"/tmp/result\", nil, 0600)\n",
            "  os.Create(\"result\")\n",
            "}\n",
        ));
        for key in [
            "hoonarqube-go:G303",
            "hoonarqube-go:G305",
            "hoonarqube-go:G307",
            "hoonarqube-go:G401",
            "hoonarqube-go:G405",
            "hoonarqube-go:G406",
        ] {
            assert!(
                found.iter().any(|found| found == key),
                "missing {key}: {found:?}"
            );
        }

        let unrelated = native_keys(concat!(
            "package p\n",
            "import (\"archive/zip\"; \"path/filepath\")\n",
            "var _ *zip.File\n",
            "type entry struct { Name string }; type reader struct { File []entry }\n",
            "func clean(r reader, root string) { for _, file := range r.File { _ = filepath.Join(root, file.Name) } }\n",
        ));
        assert!(
            !unrelated.iter().any(|key| key == "hoonarqube-go:G305"),
            "unrelated File fields are not archive readers: {unrelated:?}"
        );
    }

    #[test]
    fn native_staticcheck_local_semantics_find_bad_and_keep_good_clean() {
        let found = native_keys(concat!(
            "package p\n",
            "import (\"context\"; \"os\"; \"os/exec\")\n",
            "func takes(ctx context.Context) {}\n",
            "func bad() {\n",
            "  takes(nil); exec.CommandContext(nil, \"true\")\n",
            "  value := first(); value = second(); _ = value\n",
            "  var values map[string]int; values[\"x\"] = 1\n",
            "  var later map[string]int = nil; later = nil; later[\"x\"] = 1\n",
            "  file, err := os.Open(\"x\"); defer file.Close(); if err != nil { return }\n",
            "  for i := 0; i < 10; j++ { println(j) }\n",
            "}\n",
        ));
        for key in [
            "hoonarqube-go:SA1012",
            "hoonarqube-go:SA4006",
            "hoonarqube-go:SA4008",
            "hoonarqube-go:SA5000",
            "hoonarqube-go:SA5001",
        ] {
            assert!(
                found.iter().any(|found| found == key),
                "missing {key}: {found:?}"
            );
        }
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-go:SA5000")
                .count(),
            2,
            "explicit nil initialization and reassignment stay nil: {found:?}",
        );

        let clean = native_keys(concat!(
            "package p\n",
            "import (\"context\"; \"os\")\n",
            "func takes(ctx context.Context) {}\n",
            "func good() {\n",
            "  takes(context.TODO())\n",
            "  value := first(); _ = value; value = second(); _ = value\n",
            "  total := 1; total += 2; println(total)\n",
            "  values := make(map[string]int); values[\"x\"] = 1\n",
            "  for i := 0; i < 10; total++ { if ready() { i++ } }\n",
            "  file, err := os.Open(\"x\"); if err != nil { return }; defer file.Close()\n",
            "  for i := 0; i < 10; i++ { println(i) }\n",
            "}\n",
        ));
        for key in [
            "hoonarqube-go:SA1012",
            "hoonarqube-go:SA4006",
            "hoonarqube-go:SA4008",
            "hoonarqube-go:SA5000",
            "hoonarqube-go:SA5001",
        ] {
            assert!(
                !clean.iter().any(|found| found == key),
                "unexpected {key}: {clean:?}"
            );
        }
    }

    #[test]
    fn native_loop_update_tracks_writes_not_reads() {
        let found = native_keys(concat!(
            "package p\n",
            "func bad() {\n",
            "  for i := 0; i < 10; j++ { value = i }\n",
            "}\n",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-go:SA4008")
                .count(),
            1,
            "reading the condition variable does not update it: {found:?}",
        );
    }
}
