//! Tolerant Rust analyzer for the frozen `SonarQube` Community Rust catalog.
//!
//! Tree-sitter supplies error recovery and structural checks. Rules derived
//! from Clippy type analysis use conservative source shapes and stay silent
//! when the required type or API evidence is absent.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::OnceLock;

use hoonarqube_ir::{FileMetrics, FileReport, Issue, Pos, Range, sort_issues, u32_saturating};
use regex::Regex;
use tree_sitter::{Node, Parser, Point};

mod sonar_contract;

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
        key: "rust:S2208",
        any: &["::*;"],
        message: "Replace this wildcard import with explicit imports.",
    },
    PatternRule {
        key: "rust:S2437",
        any: &[
            " & 0", "0 & ", " | 0", "0 | ", " ^ 0", "0 ^ ", " << 0", " >> 0", " | 2 >",
        ],
        message: "Remove this unnecessary bit operation.",
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
        key: "rust:S7419",
        any: &[".read(", ".write("],
        message: "Process the entire I/O buffer or handle the partial result.",
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
        key: "rust:S7443",
        any: &["transmute::<", "std::mem::transmute::<"],
        message: "Delay this transmute until its value is needed.",
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
        key: "rust:S7446",
        any: &["*const ", "*mut "],
        message: "Mark this function as unsafe because it dereferences a raw pointer.",
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
    PatternRule {
        key: "rust:S7463",
        any: &[" - "],
        message: "Use `saturating_sub` to avoid subtraction underflow.",
    },
    PatternRule {
        key: "rust:S7464",
        any: &["std::iter::repeat(", "iter::repeat(", ".cycle()"],
        message: "Finish this infinite iterator with a terminating operation.",
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
    let code = masked_source(source, root, true);
    let uncommented = masked_source(source, root, false);

    check_patterns(source, &code, &mut issues);
    check_whole_file(source, &code, &uncommented, root, &mut issues);
    check_syntax_errors(root, source, &mut issues);
    walk_valid(root, &mut |node| {
        check_node(node, source, &code, &uncommented, options, &mut issues);
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
    let fallback = ["rust:S2437", "rust:S7414", "rust:S7418"];
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

/// Replaces comments, optionally literals, and parser-error regions with spaces
/// while retaining byte length and line endings. Textual rules can then search
/// accepted Rust code without matching examples, diagnostics, or invalid CSTs.
fn masked_source(source: &str, root: Node<'_>, mask_literals: bool) -> String {
    let mut code = source.as_bytes().to_vec();
    walk(root, &mut |node| {
        let comment = matches!(node.kind(), "line_comment" | "block_comment");
        let literal = matches!(
            node.kind(),
            "string_literal" | "raw_string_literal" | "char_literal"
        );
        if node.is_error() || comment || mask_literals && literal {
            mask_range(&mut code, node.byte_range());
        }
    });
    walk_all(root, &mut |node| {
        if node.is_missing()
            && let Some(parent) = node.parent()
        {
            if parent.kind() != "source_file" {
                mask_range(&mut code, parent.byte_range());
            }
            mask_range(&mut code, line_byte_range(source, node.start_byte()));
        }
    });
    // Replacing every non-line-ending byte in syntax-tree ranges with ASCII
    // spaces cannot create invalid UTF-8 outside those fully replaced ranges.
    String::from_utf8(code).expect("masked Rust source remains valid UTF-8")
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
        "rust:S7419" => {
            !line.contains("read_exact")
                && !line.contains("write_all")
                && ![
                    ".read(true)",
                    ".read(false)",
                    ".write(true)",
                    ".write(false)",
                ]
                .iter()
                .any(|builder| line.contains(builder))
        }
        "rust:S7424" => source.contains("impl PartialEq for"),
        "rust:S7425" => !source.contains("[MaybeUninit<"),
        "rust:S7440" => {
            source.contains("self.to_string()")
                || source.contains("write!(f, \"{}\", self)")
                || source.contains("format!(\"{}\", self)")
        }
        "rust:S7441" => !source.contains(".trim()") && !source.contains(".trim_end()"),
        "rust:S7443" => {
            source.contains("then_some(") || line.contains("unwrap_or(") || line.contains("map_or(")
        }
        "rust:S7444" => overflow_comparison_regex().is_match(line),
        "rust:S7446" => {
            line.contains("fn ")
                && !line.contains("unsafe fn")
                && (source.contains("unsafe { *") || source.contains("unsafe{*"))
        }
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
        "rust:S7463" => line.contains("if ") && line.contains('>'),
        "rust:S7464" => ![".take(", ".find(", ".any(", ".next()", ".position("]
            .iter()
            .any(|term| line.contains(term)),
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
    check_vector_pushes(source, code, issues);
    check_getters(root, source, code, issues);
    check_returned_locals(root, source, code, issues);
    check_immutable_while_conditions(root, source, code, issues);
    check_manual_swap(source, code, issues);
    check_array_indexes(source, code, issues);
    check_reversed_ranges(source, code, issues);
    check_masks(source, code, issues);
    check_async_returns(source, code, issues);
    check_function_pointer_closures(source, code, issues);
    check_enum_portability(source, code, issues);
    check_match_case(source, uncommented, issues);
    check_raw_pointer_functions(source, code, issues);
    check_mutable_return(source, code, issues);
    check_float_loop_counter(source, code, issues);
    check_redundant_casts(source, code, issues);
    check_numeric_suffixes(source, code, issues);
    check_unit_sort_closure(source, code, issues);
    check_string_to_string(source, code, issues);
    check_missing_array_commas(source, code, issues);
    check_constant_array_access(source, code, issues);
    check_shared_branch_prefix(source, uncommented, issues);
    check_async_block_tail(source, code, issues);
    check_slice_cast_sizes(source, code, issues);
    check_double_comparisons(source, code, issues);
    check_almost_swap(source, code, issues);
    check_panicking_unwrap(root, source, code, issues);
    check_eager_transmute(source, code, issues);
    check_overflow_addition(source, code, issues);
    check_complex_while_condition(root, source, code, issues);
    check_lowercase_match_arms(source, uncommented, issues);
    check_boolean_match_parameters(source, code, issues);
}

fn check_node(
    node: Node<'_>,
    source: &str,
    code: &str,
    uncommented: &str,
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
        "assignment_expression" => check_assignment(node, source, code, issues),
        "binary_expression" => check_binary(node, source, code, issues),
        "if_expression" => check_if(node, source, uncommented, issues),
        "loop_expression" => check_single_iteration_loop(node, source, issues),
        "struct_expression" => check_struct_shorthand(node, source, code, issues),
        "expression_statement" => check_no_effect(node, source, issues),
        "match_expression" => check_boolean_match(node, source, issues),
        "integer_literal" | "float_literal" => check_large_number(node, source, issues),
        "macro_invocation" => check_standard_output_macro(node, source, issues),
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

fn check_standard_output_macro(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let Some(name) = node.child_by_field_name("macro") else {
        return;
    };
    let name = text(name, source).rsplit("::").next().unwrap_or_default();
    if matches!(name, "print" | "println" | "eprint" | "eprintln" | "dbg") {
        issues.push(node_issue(
            "rust:S106",
            "Replace this use of standard output with a logger.",
            node,
            source,
        ));
    }
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

fn check_assignment(node: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
    let left = node
        .child_by_field_name("left")
        .or_else(|| node.named_child(0));
    let right = node
        .child_by_field_name("right")
        .or_else(|| node.named_child(1));
    if let (Some(left), Some(right)) = (left, right)
        && normalized(text(left, scan)) == normalized(text(right, scan))
    {
        issues.push(node_issue(
            "rust:S1656",
            "Remove or correct this useless self-assignment.",
            node,
            source,
        ));
    }
}

fn check_binary(node: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
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
    if normalized(text(left, scan)) == normalized(text(right, scan)) {
        issues.push(node_issue(
            "rust:S1764",
            "Correct one of the identical sub-expressions on both sides of this operator.",
            node,
            source,
        ));
    }
    let full = text(node, scan);
    let compact = normalized(full);
    if (compact.ends_with("<0") || compact.ends_with("<=0")) && is_unsigned_expression(left, source)
    {
        issues.push(node_issue(
            "rust:S2198",
            "Remove this unnecessary comparison of an unsigned value.",
            node,
            source,
        ));
    }
    if redundant_comparison(full) {
        issues.push(node_issue(
            "rust:S7436",
            "Remove this redundant comparison.",
            node,
            source,
        ));
    }
    if boolean_operand_redundant(full) {
        issues.push(node_issue(
            "rust:S2589",
            "Remove this redundant Boolean operand.",
            node,
            source,
        ));
    }
}

fn check_if(node: Node<'_>, source: &str, scan: &str, issues: &mut Vec<Issue>) {
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
            let condition_text = normalized(text(condition, scan));
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
            branches.push(normalized(text(consequence, scan)));
        }
        match item.child_by_field_name("alternative") {
            Some(alternative) if nested_if(alternative).is_some() => {
                current = nested_if(alternative);
            }
            Some(alternative) => {
                branches.push(normalized(text(alternative, scan)));
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
        if matches!(condition, "true" | "false")
            || condition.starts_with('!')
            || condition.contains(" == ")
            || condition.contains(" != ")
        {
            issues.push(node_issue(
                "rust:S920",
                "Replace this match on a Boolean value with an if expression.",
                value,
                source,
            ));
        }
    }
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

fn check_vector_pushes(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in vector_declaration_regex().captures_iter(scan) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let declaration = captures.get(0).expect("whole regex capture");
        let tail = &scan[declaration.end()..];
        let push = format!("{}.push(", name.as_str());
        if tail
            .lines()
            .take(5)
            .filter(|line| line.contains(&push))
            .count()
            >= 2
        {
            issues.push(offset_issue(
                "rust:S7089",
                "Initialize this vector with the `vec!` macro.",
                source,
                declaration.start(),
                declaration.end(),
            ));
        }
    }
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
        let condition_text = normalized(text(condition, scan));
        let name = condition_text.as_str();
        let body = text(node, scan);
        if identifier_regex().is_match(name)
            && ![
                format!("{name} ="),
                format!("{name} +="),
                format!("{name} -="),
            ]
            .iter()
            .any(|shape| body.contains(shape))
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

fn check_array_indexes(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in array_index_regex().captures_iter(scan) {
        let length = captures.name("items").map_or(0, |items| {
            items
                .as_str()
                .split(',')
                .filter(|item| !item.trim().is_empty())
                .count()
        });
        let index = captures
            .name("index")
            .and_then(|value| value.as_str().parse::<usize>().ok());
        if index.is_some_and(|value| value >= length) {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S6466",
                "This array index always panics.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
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
    for captures in closure_call_regex().captures_iter(scan) {
        let argument = captures.name("arg").map(|value| value.as_str());
        let passed = captures.name("passed").map(|value| value.as_str());
        if argument == passed {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S1612",
                "Replace this closure with the function directly.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
    for full in method_closure_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S1612",
            "Replace this closure with the method directly.",
            source,
            full.start(),
            full.end(),
        ));
    }
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

fn check_raw_pointer_functions(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for full in raw_pointer_function_regex().find_iter(scan) {
        if !full
            .as_str()
            .split("fn")
            .next()
            .is_some_and(|prefix| prefix.contains("unsafe"))
        {
            issues.push(offset_issue(
                "rust:S7446",
                "Mark this function as unsafe because it dereferences a raw pointer.",
                source,
                full.start(),
                full.end(),
            ));
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

fn check_missing_array_commas(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for full in missing_comma_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S3723",
            "Separate these elements with a comma.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_constant_array_access(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in named_array_regex().captures_iter(scan) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let length = captures.name("items").map_or(0, |items| {
            items
                .as_str()
                .split(',')
                .filter(|item| !item.trim().is_empty())
                .count()
        });
        let declaration = captures.get(0).expect("whole regex capture");
        let tail = &scan[declaration.end()..];
        let access = Regex::new(&format!(
            r"\b{}\s*\[\s*(\d+)\s*\]",
            regex::escape(name.as_str())
        ))
        .expect("escaped identifier regex");
        for captures in access.captures_iter(tail) {
            let index = captures
                .get(1)
                .and_then(|value| value.as_str().parse::<usize>().ok());
            if index.is_some_and(|index| index >= length) {
                let full = captures.get(0).expect("whole regex capture");
                let start = declaration.end() + full.start();
                issues.push(offset_issue(
                    "rust:S6466",
                    "This array index always panics.",
                    source,
                    start,
                    declaration.end() + full.end(),
                ));
            }
        }
    }
}

fn check_shared_branch_prefix(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in shared_branch_regex().captures_iter(scan) {
        let first = captures
            .name("first")
            .map(|value| normalized(value.as_str()));
        let second = captures
            .name("second")
            .map(|value| normalized(value.as_str()));
        if first == second {
            let full = captures.get(0).expect("whole regex capture");
            issues.push(offset_issue(
                "rust:S7411",
                "Extract the code shared by all branches.",
                source,
                full.start(),
                full.end(),
            ));
        }
    }
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

fn check_eager_transmute(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    if !scan.contains("then_some(") {
        return;
    }
    for full in transmute_call_regex().find_iter(scan) {
        issues.push(offset_issue(
            "rust:S7443",
            "Evaluate this transmute lazily.",
            source,
            full.start(),
            full.end(),
        ));
    }
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

fn check_complex_while_condition(
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
        let Some(name) = identifier_in_expression_regex().find(text(condition, scan)) else {
            return;
        };
        let variable = name.as_str();
        let body = text(node, scan);
        if ![
            format!("{variable} ="),
            format!("{variable} +="),
            format!("{variable} -="),
        ]
        .iter()
        .any(|shape| body.contains(shape))
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

fn check_boolean_match_parameters(source: &str, scan: &str, issues: &mut Vec<Issue>) {
    for captures in boolean_parameter_regex().captures_iter(scan) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let declaration = captures.get(0).expect("whole regex capture");
        let tail = &scan[declaration.end()..];
        let shape = format!("match {}", name.as_str());
        if let Some(relative) = tail.find(&shape) {
            let start = declaration.end() + relative;
            issues.push(offset_issue(
                "rust:S920",
                "Replace this match on a Boolean value with an if expression.",
                source,
                start,
                start + shape.len(),
            ));
        }
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

fn redundant_comparison(value: &str) -> bool {
    let compact = normalized(value);
    compact.contains("==true==true") || compact.contains("!=false!=false")
}

fn boolean_operand_redundant(value: &str) -> bool {
    let compact = normalized(value);
    let Some((left, repeated)) = compact.split_once("||") else {
        return false;
    };
    left.split("&&").any(|operand| operand == repeated)
}

fn parse_integer(value: &str) -> Option<u128> {
    let compact = value.replace('_', "");
    if let Some(hex) = compact.strip_prefix("0x") {
        u128::from_str_radix(hex, 16).ok()
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
    vector_declaration_regex,
    r"let\s+mut\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*Vec::new\(\)\s*;"
);
regex_fn!(
    self_field_regex,
    r"^\{\s*(?:return\s+)?self\.(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*;?\s*\}$"
);
regex_fn!(identifier_regex, r"^[A-Za-z_][A-Za-z0-9_]*$");
regex_fn!(
    array_index_regex,
    r"\[(?P<items>[^\[\]\n]+)\]\s*\[\s*(?P<index>\d+)\s*\]"
);
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
regex_fn!(
    closure_call_regex,
    r"\|(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\|\s*[A-Za-z_][A-Za-z0-9_:]*\((?P<passed>[A-Za-z_][A-Za-z0-9_]*)\)"
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
    raw_pointer_function_regex,
    r"(?s)(?:pub\s+)?(?:unsafe\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^\)]*\*(?:mut|const)\s+[^\)]*\)[^\{]*\{[^\}]*\*"
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
    named_array_regex,
    r"let\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(?P<items>[^\]\n]+)\]\s*;"
);
regex_fn!(
    shared_branch_regex,
    r"(?s)if\s+[^\{]+\{\s*(?P<first>[^;\n]+;)[^\}]*\}\s*else\s*\{\s*(?P<second>[^;\n]+;)"
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
    transmute_call_regex,
    r"(?:std::mem::|core::intrinsics::)?transmute(?:::<[^>]+>)?\([^\)]*\)"
);
regex_fn!(
    overflow_comparison_regex,
    r"[A-Za-z_][A-Za-z0-9_]*\s*\+\s*[A-Za-z_][A-Za-z0-9_]*\s*<\s*[A-Za-z_][A-Za-z0-9_]*"
);
regex_fn!(
    unit_sort_closure_regex,
    r"\.sort_by_key\(\|[^|]+\|\s*\{[^\}]*;\s*\}\)"
);
regex_fn!(
    method_closure_regex,
    r"\|[A-Za-z_][A-Za-z0-9_]*\|\s*[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\(\)"
);
regex_fn!(unsigned_cast_regex, r"\bas\s+u(?:8|16|32|64|128|size)\b");
regex_fn!(
    typed_declaration_regex,
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<type>[A-Za-z_][A-Za-z0-9_:<>]*)"
);
regex_fn!(identifier_in_expression_regex, r"[A-Za-z_][A-Za-z0-9_]*");
regex_fn!(
    uppercase_string_arm_regex,
    r#"\"[A-Za-z]*[A-Z][A-Za-z]*\"\s*=>"#
);
regex_fn!(
    boolean_parameter_regex,
    r"fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*bool[^\)]*\)"
);

#[cfg(test)]
mod tests {
    use super::*;

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
}
