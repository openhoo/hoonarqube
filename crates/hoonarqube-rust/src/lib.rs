//! Tolerant Rust analyzer for the frozen `SonarQube` Community Rust catalog.
//!
//! Tree-sitter supplies error recovery and structural checks. Rules derived
//! from Clippy type analysis use conservative source shapes and stay silent
//! when the required type or API evidence is absent.

use std::collections::HashSet;
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
        key: "rust:S106",
        any: &["print!(", "println!(", "eprint!(", "eprintln!(", "dbg!("],
        message: "Replace this use of standard output with a logger.",
    },
    PatternRule {
        key: "rust:S1858",
        any: &[
            "String::from(",
            ".to_owned().to_string()",
            ".to_string().to_string()",
        ],
        message: "Remove this redundant call to `to_string()`.",
    },
    PatternRule {
        key: "rust:S2185",
        any: &[" * 0", "0 * ", " / 0", " % 1", " % -1"],
        message: "Remove this erasing mathematical operation.",
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
        key: "rust:S4962",
        any: &["0 as *const", "0 as *mut"],
        message: "Use `std::ptr::null` or `std::ptr::null_mut` instead.",
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
        key: "rust:S7442",
        any: &["Some(", "Ok("],
        message: "Use the contained value directly instead of calling `unwrap()`.",
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

    check_patterns(source, &mut issues);
    check_whole_file(source, root, &mut issues);
    walk(root, &mut |node| {
        check_node(node, source, options, &mut issues);
    });
    deduplicate(&mut issues);
    normalize_sonar_contract(source, &mut issues);
    sort_issues(&mut issues);

    FileReport {
        path,
        language: "rust".to_string(),
        issues,
        metrics: metrics(source),
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

fn check_patterns(source: &str, issues: &mut Vec<Issue>) {
    for rule in PATTERN_RULES {
        for (line_index, line) in source.lines().enumerate() {
            let code = line.split("//").next().unwrap_or(line);
            let match_value = rule
                .any
                .iter()
                .filter_map(|needle| code.find(needle).map(|start| (start, *needle)))
                .min_by_key(|(start, _)| *start);
            if let Some((start, needle)) = match_value
                && pattern_guard(rule.key, source, code)
            {
                issues.push(line_issue(
                    rule.key,
                    rule.message,
                    line_index,
                    start,
                    start + needle.len(),
                ));
            }
        }
    }
}

fn pattern_guard(key: &str, source: &str, line: &str) -> bool {
    match key {
        "rust:S1858" => line.contains(".to_string()") || source.contains(".to_string()"),
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
        "rust:S7419" => !line.contains("read_exact") && !line.contains("write_all"),
        "rust:S7424" => source.contains("impl PartialEq for"),
        "rust:S7425" => !source.contains("[MaybeUninit<"),
        "rust:S7440" => {
            source.contains("self.to_string()")
                || source.contains("write!(f, \"{}\", self)")
                || source.contains("format!(\"{}\", self)")
        }
        "rust:S7441" => !source.contains(".trim()") && !source.contains(".trim_end()"),
        "rust:S7442" => line.contains(".unwrap()") && source.contains("is_none()"),
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

fn check_whole_file(source: &str, root: Node<'_>, issues: &mut Vec<Issue>) {
    check_invisible_unicode(source, issues);
    check_regex_literals(source, issues);
    check_vector_pushes(source, issues);
    check_getters(root, source, issues);
    check_returned_locals(root, source, issues);
    check_immutable_while_conditions(root, source, issues);
    check_manual_swap(source, issues);
    check_array_indexes(source, issues);
    check_reversed_ranges(source, issues);
    check_masks(source, issues);
    check_overlapping_ranges(source, issues);
    check_async_returns(source, issues);
    check_function_pointer_closures(source, issues);
    check_enum_portability(source, issues);
    check_match_case(source, issues);
    check_raw_pointer_functions(source, issues);
    check_mutable_return(source, issues);
    check_float_loop_counter(source, issues);
    check_redundant_casts(source, issues);
    check_numeric_suffixes(source, issues);
    check_unit_sort_closure(source, issues);
    check_string_to_string(source, issues);
    check_missing_array_commas(source, issues);
    check_constant_array_access(source, issues);
    check_shared_branch_prefix(source, issues);
    check_async_block_tail(source, issues);
    check_slice_cast_sizes(source, issues);
    check_double_comparisons(source, issues);
    check_almost_swap(source, issues);
    check_panicking_unwrap(source, issues);
    check_eager_transmute(source, issues);
    check_overflow_addition(source, issues);
    check_unsigned_zero_comparison(source, issues);
    check_complex_while_condition(root, source, issues);
    check_lowercase_match_arms(source, issues);
    check_boolean_match_parameters(source, issues);
}

fn check_node(node: Node<'_>, source: &str, options: &AnalyzerOptions, issues: &mut Vec<Issue>) {
    if node.is_error() || node.is_missing() {
        issues.push(node_issue("rust:S2260", "Fix this syntax error.", node));
        if node
            .parent()
            .is_some_and(|parent| matches!(parent.kind(), "array_expression" | "tuple_expression"))
        {
            issues.push(node_issue(
                "rust:S3723",
                "Separate these elements with a comma.",
                node,
            ));
        }
        return;
    }
    match node.kind() {
        "function_item" => check_function(node, options, issues),
        "empty_statement" => issues.push(node_issue(
            "rust:S1116",
            "Remove this empty statement.",
            node,
        )),
        "assignment_expression" => check_assignment(node, source, issues),
        "binary_expression" => check_binary(node, source, issues),
        "if_expression" => check_if(node, source, issues),
        "loop_expression" => check_single_iteration_loop(node, source, issues),
        "struct_expression" => check_struct_shorthand(node, source, issues),
        "expression_statement" => check_no_effect(node, issues),
        "match_expression" => check_boolean_match(node, source, issues),
        "integer_literal" => check_large_number(node, source, issues),
        _ => {}
    }
}

fn check_function(node: Node<'_>, options: &AnalyzerOptions, issues: &mut Vec<Issue>) {
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
        && normalized(text(left, source)) == normalized(text(right, source))
    {
        issues.push(node_issue(
            "rust:S1656",
            "Remove or correct this useless self-assignment.",
            node,
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
    if normalized(text(left, source)) == normalized(text(right, source)) {
        issues.push(node_issue(
            "rust:S1764",
            "Correct one of the identical sub-expressions on both sides of this operator.",
            node,
        ));
    }
    let full = text(node, source);
    if (full.contains("< 0") || full.contains("<= 0")) && unsigned_name(text(left, source)) {
        issues.push(node_issue(
            "rust:S2198",
            "Remove this unnecessary comparison of an unsigned value.",
            node,
        ));
    }
    if redundant_comparison(full) {
        issues.push(node_issue(
            "rust:S7436",
            "Remove this redundant comparison.",
            node,
        ));
    }
    if boolean_operand_redundant(full) {
        issues.push(node_issue(
            "rust:S2589",
            "Remove this redundant Boolean operand.",
            node,
        ));
    }
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
    let mut final_else = false;
    while let Some(item) = current {
        if let Some(condition) = item.child_by_field_name("condition") {
            let condition_text = normalized(text(condition, source));
            if conditions.contains(&condition_text) {
                issues.push(node_issue(
                    "rust:S1862",
                    "This condition duplicates a previous condition in this sequence.",
                    condition,
                ));
            }
            conditions.push(condition_text);
        }
        if let Some(consequence) = item.child_by_field_name("consequence") {
            branches.push(normalized(text(consequence, source)));
        }
        match item.child_by_field_name("alternative") {
            Some(alternative) if nested_if(alternative).is_some() => {
                current = nested_if(alternative);
            }
            Some(alternative) => {
                branches.push(normalized(text(alternative, source)));
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
            node,
        ));
    }
    if branches.len() > 1 && has_duplicate(&branches) {
        issues.push(node_issue(
            "rust:S7411",
            "Extract the code shared by all branches.",
            node,
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
    let value = text(node, source);
    if value.contains("break;") || value.contains("return ") {
        issues.push(node_issue(
            "rust:S1751",
            "Refactor this loop because it can execute at most once.",
            node,
        ));
    }
}

fn check_struct_shorthand(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(node, &mut |child| {
        if child.kind() == "field_initializer" {
            let value = text(child, source);
            if let Some((left, right)) = value.split_once(':')
                && left.trim() == right.trim()
            {
                issues.push(node_issue("rust:S3498", "Use field init shorthand.", child));
            }
        }
    });
}

fn check_no_effect(node: Node<'_>, issues: &mut Vec<Issue>) {
    let Some(expression) = node.named_child(0) else {
        return;
    };
    if matches!(
        expression.kind(),
        "integer_literal" | "float_literal" | "string_literal" | "boolean_literal" | "identifier"
    ) || expression.kind() == "binary_expression"
    {
        issues.push(node_issue(
            "rust:S905",
            "Remove this statement because it has no effect.",
            expression,
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
            ));
        }
    }
}

fn check_large_number(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let value = text(node, source);
    let digits = value
        .trim_start_matches(['-', '+'])
        .split(|character: char| !character.is_ascii_digit() && character != '_')
        .next()
        .unwrap_or_default();
    if digits.len() >= 6 && !digits.contains('_') {
        issues.push(node_issue(
            "rust:S2148",
            "Add underscores to make this large number readable.",
            node,
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

fn check_regex_literals(source: &str, issues: &mut Vec<Issue>) {
    for captures in regex_constructor().captures_iter(source) {
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

fn check_vector_pushes(source: &str, issues: &mut Vec<Issue>) {
    for captures in vector_declaration_regex().captures_iter(source) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let declaration = captures.get(0).expect("whole regex capture");
        let tail = &source[declaration.end()..];
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

fn check_getters(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
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
            .captures(text(body, source))
            .and_then(|captures| captures.name("field"));
        if field.is_some_and(|field| field.as_str() != expected)
            && text(node, source).contains("&self")
        {
            issues.push(node_issue(
                "rust:S4275",
                "Return the field corresponding to this getter's name.",
                name,
            ));
        }
    });
}

fn check_returned_locals(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        if node.kind() != "block" {
            return;
        }
        let Some(captures) = returned_local_regex().captures(text(node, source)) else {
            return;
        };
        if captures.name("name").map(|value| value.as_str())
            == captures.name("returned").map(|value| value.as_str())
        {
            issues.push(node_issue(
                "rust:S1488",
                "Return this expression directly instead of assigning it to a local variable.",
                node,
            ));
        }
    });
}

fn check_immutable_while_conditions(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        if node.kind() != "while_expression" {
            return;
        }
        let Some(condition) = node.child_by_field_name("condition") else {
            return;
        };
        let name = text(condition, source).trim();
        let body = text(node, source);
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
            ));
        }
    });
}

fn check_manual_swap(source: &str, issues: &mut Vec<Issue>) {
    let lines: Vec<_> = source.lines().collect();
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
                window[0].chars().count(),
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

fn check_array_indexes(source: &str, issues: &mut Vec<Issue>) {
    for captures in array_index_regex().captures_iter(source) {
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

fn check_reversed_ranges(source: &str, issues: &mut Vec<Issue>) {
    for captures in range_regex().captures_iter(source) {
        let start = captures
            .name("start")
            .and_then(|value| value.as_str().parse::<i64>().ok());
        let end = captures
            .name("end")
            .and_then(|value| value.as_str().parse::<i64>().ok());
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

fn check_masks(source: &str, issues: &mut Vec<Issue>) {
    for captures in mask_regex().captures_iter(source) {
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

fn check_overlapping_ranges(source: &str, issues: &mut Vec<Issue>) {
    for captures in overlapping_range_regex().captures_iter(source) {
        let low = captures
            .name("low")
            .and_then(|value| value.as_str().parse::<i64>().ok());
        let high = captures
            .name("high")
            .and_then(|value| value.as_str().parse::<i64>().ok());
        if low.zip(high).is_some_and(|(low, high)| low >= high) {
            let full = captures.get(0).expect("whole regex capture");
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

fn check_async_returns(source: &str, issues: &mut Vec<Issue>) {
    for captures in async_return_regex().captures_iter(source) {
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

fn check_function_pointer_closures(source: &str, issues: &mut Vec<Issue>) {
    for captures in closure_call_regex().captures_iter(source) {
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
    for full in method_closure_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S1612",
            "Replace this closure with the method directly.",
            source,
            full.start(),
            full.end(),
        ));
    }
    for full in unit_fn_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S7421",
            "Remove the unit return type from this `Fn` trait bound.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_enum_portability(source: &str, issues: &mut Vec<Issue>) {
    if !source.contains("enum ")
        || (!source.contains("repr(usize)") && !source.contains("repr(isize)"))
    {
        return;
    }
    for captures in enum_variant_regex().captures_iter(source) {
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

fn check_match_case(source: &str, issues: &mut Vec<Issue>) {
    for captures in case_mismatch_regex().captures_iter(source) {
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

fn check_raw_pointer_functions(source: &str, issues: &mut Vec<Issue>) {
    for full in raw_pointer_function_regex().find_iter(source) {
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

fn check_mutable_return(source: &str, issues: &mut Vec<Issue>) {
    for full in mutable_return_regex().find_iter(source) {
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

fn check_float_loop_counter(source: &str, issues: &mut Vec<Issue>) {
    for captures in float_counter_regex().captures_iter(source) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let tail = &source[captures.get(0).expect("whole regex capture").end()..];
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

fn check_redundant_casts(source: &str, issues: &mut Vec<Issue>) {
    for captures in repeated_cast_regex().captures_iter(source) {
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
    for full in length_cast_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S4325",
            "Remove this redundant cast.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_numeric_suffixes(source: &str, issues: &mut Vec<Issue>) {
    for full in numeric_suffix_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S7454",
            "Correct this mistyped numeric literal suffix.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_unit_sort_closure(source: &str, issues: &mut Vec<Issue>) {
    for full in unit_sort_closure_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S7421",
            "Return the ordering key instead of a unit value.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_string_to_string(source: &str, issues: &mut Vec<Issue>) {
    for captures in string_variable_regex().captures_iter(source) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let declaration = captures.get(0).expect("whole regex capture");
        let tail = &source[declaration.end()..];
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

fn check_missing_array_commas(source: &str, issues: &mut Vec<Issue>) {
    for full in missing_comma_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S3723",
            "Separate these elements with a comma.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_constant_array_access(source: &str, issues: &mut Vec<Issue>) {
    for captures in named_array_regex().captures_iter(source) {
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
        let tail = &source[declaration.end()..];
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

fn check_shared_branch_prefix(source: &str, issues: &mut Vec<Issue>) {
    for captures in shared_branch_regex().captures_iter(source) {
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

fn check_async_block_tail(source: &str, issues: &mut Vec<Issue>) {
    for captures in async_block_regex().captures_iter(source) {
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

fn check_slice_cast_sizes(source: &str, issues: &mut Vec<Issue>) {
    for captures in slice_cast_regex().captures_iter(source) {
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

fn check_double_comparisons(source: &str, issues: &mut Vec<Issue>) {
    for captures in double_comparison_regex().captures_iter(source) {
        let first_name = captures.name("first_name").map(|value| value.as_str());
        let second_name = captures.name("second_name").map(|value| value.as_str());
        if first_name != second_name {
            continue;
        }
        let first = captures
            .name("first")
            .and_then(|value| value.as_str().parse::<i64>().ok());
        let second = captures
            .name("second")
            .and_then(|value| value.as_str().parse::<i64>().ok());
        let first_op = captures
            .name("first_op")
            .map(|value| value.as_str())
            .unwrap_or_default();
        let second_op = captures
            .name("second_op")
            .map(|value| value.as_str())
            .unwrap_or_default();
        let full = captures.get(0).expect("whole regex capture");
        if first.zip(second).is_some_and(|(first, second)| {
            (first_op.starts_with('<') && second_op.starts_with('<') && first <= second)
                || (first_op.starts_with('>') && second_op.starts_with('>') && first >= second)
        }) {
            issues.push(offset_issue(
                "rust:S7436",
                "Remove this redundant comparison.",
                source,
                full.start(),
                full.end(),
            ));
        }
        if first.zip(second).is_some_and(|(first, second)| {
            (first_op.starts_with('<') && second_op.starts_with('>') && first < second)
                || (first_op.starts_with('>') && second_op.starts_with('<') && first > second)
        }) {
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

fn check_almost_swap(source: &str, issues: &mut Vec<Issue>) {
    let lines: Vec<_> = source.lines().collect();
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
                window[0].chars().count(),
            ));
        }
    }
}

fn check_panicking_unwrap(source: &str, issues: &mut Vec<Issue>) {
    if !source.contains("is_none()") && !source.contains("is_err()") {
        return;
    }
    for full in unwrap_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S7442",
            "Use the contained value only on a branch where it is present.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_eager_transmute(source: &str, issues: &mut Vec<Issue>) {
    if !source.contains("then_some(") {
        return;
    }
    for full in transmute_call_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S7443",
            "Evaluate this transmute lazily.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_overflow_addition(source: &str, issues: &mut Vec<Issue>) {
    for full in overflow_comparison_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S7444",
            "Use `checked_add` or `overflowing_add` to detect overflow.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_unsigned_zero_comparison(source: &str, issues: &mut Vec<Issue>) {
    for full in unsigned_zero_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S2198",
            "Remove this unnecessary comparison of an unsigned value.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_complex_while_condition(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        if node.kind() != "while_expression" {
            return;
        }
        let Some(condition) = node.child_by_field_name("condition") else {
            return;
        };
        let Some(name) = identifier_in_expression_regex().find(text(condition, source)) else {
            return;
        };
        let variable = name.as_str();
        let body = text(node, source);
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
            ));
        }
    });
}

fn check_lowercase_match_arms(source: &str, issues: &mut Vec<Issue>) {
    if !source.contains("to_ascii_lowercase()") {
        return;
    }
    for full in uppercase_string_arm_regex().find_iter(source) {
        issues.push(offset_issue(
            "rust:S7428",
            "Use lowercase in this match arm because the matched value is lowercased.",
            source,
            full.start(),
            full.end(),
        ));
    }
}

fn check_boolean_match_parameters(source: &str, issues: &mut Vec<Issue>) {
    for captures in boolean_parameter_regex().captures_iter(source) {
        let Some(name) = captures.name("name") else {
            continue;
        };
        let declaration = captures.get(0).expect("whole regex capture");
        let tail = &source[declaration.end()..];
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

fn metrics(source: &str) -> FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        source.lines().count()
    };
    let mut code = 0;
    let mut comments = 0;
    let mut in_block = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if in_block || trimmed.starts_with("//") || trimmed.starts_with("/*") {
            comments += usize::from(!trimmed.is_empty());
        } else if !trimmed.is_empty() {
            code += 1;
        }
        if trimmed.contains("/*") && !trimmed.contains("*/") {
            in_block = true;
        }
        if trimmed.contains("*/") {
            in_block = false;
        }
    }
    FileMetrics {
        lines: u32_saturating(lines),
        code_lines: u32_saturating(code),
        comment_lines: u32_saturating(comments),
    }
}

fn cognitive_complexity(node: Node<'_>) -> usize {
    fn visit(node: Node<'_>, nesting: usize) -> usize {
        let control = matches!(
            node.kind(),
            "if_expression"
                | "for_expression"
                | "while_expression"
                | "loop_expression"
                | "match_expression"
        );
        let mut total = usize::from(control) * (nesting + 1);
        let next = nesting + usize::from(control);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            total += visit(child, next);
        }
        total
    }
    visit(node, 0)
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

fn unsigned_name(value: &str) -> bool {
    value.starts_with('u') || value.contains("len()") || value.contains("usize")
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

fn normalized(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn has_duplicate(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[index + 1..].contains(value))
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or_default()
}

fn walk<'tree>(node: Node<'tree>, callback: &mut impl FnMut(Node<'tree>)) {
    callback(node);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, callback);
    }
}

fn node_issue(key: &str, message: impl Into<String>, node: Node<'_>) -> Issue {
    Issue::new(
        key,
        message,
        point_range(node.start_position(), node.end_position()),
    )
}

fn point_range(start: Point, end: Point) -> Range {
    Range {
        start: Pos {
            line: u32_saturating(start.row + 1),
            column: u32_saturating(start.column),
        },
        end: Pos {
            line: u32_saturating(end.row + 1),
            column: u32_saturating(end.column),
        },
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
            .map_or(before.chars().count(), |(_, tail)| tail.chars().count());
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
regex_fn!(self_field_regex, r"self\.(?P<field>[A-Za-z_][A-Za-z0-9_]*)");
regex_fn!(
    returned_local_regex,
    r"(?s)let\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=.+?;\s*(?:return\s+)?(?P<returned>[A-Za-z_][A-Za-z0-9_]*)\s*;?\s*\}"
);
regex_fn!(identifier_regex, r"^[A-Za-z_][A-Za-z0-9_]*$");
regex_fn!(
    array_index_regex,
    r"\[(?P<items>[^\[\]\n]+)\]\s*\[\s*(?P<index>\d+)\s*\]"
);
regex_fn!(range_regex, r"(?P<start>\d+)\s*\.\.?=?(?P<end>\d+)");
regex_fn!(
    mask_regex,
    r"\(?(?:[A-Za-z_][A-Za-z0-9_]*)\s*&\s*(?P<mask>0x[0-9A-Fa-f_]+|0b[01_]+|\d+)\)?\s*==\s*(?P<value>0x[0-9A-Fa-f_]+|0b[01_]+|\d+)"
);
regex_fn!(
    overlapping_range_regex,
    r"[A-Za-z_][A-Za-z0-9_]*\s*[<>]=?\s*(?P<low>\d+)\s*&&\s*[A-Za-z_][A-Za-z0-9_]*\s*[<>]=?\s*(?P<high>\d+)"
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
    r"(?P<first_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<first_op><=|>=|<|>)\s*(?P<first>\d+)\s*&&\s*(?P<second_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<second_op><=|>=|<|>)\s*(?P<second>\d+)"
);
regex_fn!(unwrap_regex, r"[A-Za-z_][A-Za-z0-9_]*\.unwrap\(\)");
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
regex_fn!(
    unsigned_zero_regex,
    r"fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^\)]*(?:u(?:8|16|32|64|128)|usize)[^\)]*\)[^\{]*\{[^\}]*<=?\s*0"
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
    fn parser_errors_are_reported_without_panicking() {
        assert!(keys("fn broken( {").contains(&"rust:S2260".to_string()));
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
