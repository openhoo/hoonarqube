//! Tolerant Go analyzer for the frozen `SonarQube` Community Go catalog.

use std::collections::HashMap;
use std::path::PathBuf;

use hoonarqube_ir::{FileMetrics, FileReport, Issue, Pos, Range, sort_issues, u32_saturating};
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

/// Analyze one Go source file. Tree-sitter error recovery preserves valid
/// subtrees while `go:S2260` reports every syntax error or missing token.
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
    let mut issues = Vec::new();

    check_lines(path.as_path(), source, options, &mut issues);
    check_header(source, options, &mut issues);
    check_textual(source, root, &mut issues);
    walk(root, &mut |node| {
        check_node(node, source, options, &mut issues);
    });
    check_duplicate_strings(root, source, options, &mut issues);
    check_duplicate_functions(root, source, &mut issues);
    sort_issues(&mut issues);

    FileReport {
        path,
        language: "go".to_string(),
        issues,
        metrics: metrics(source),
    }
}

fn check_lines(
    path: &std::path::Path,
    source: &str,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    let mut code_lines = 0_usize;
    let mut in_block_comment = false;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let comment_only =
            in_block_comment || trimmed.starts_with("//") || trimmed.starts_with("/*");
        if trimmed.contains("/*") && !trimmed.contains("*/") {
            in_block_comment = true;
        }
        if trimmed.contains("*/") {
            in_block_comment = false;
        }
        if !trimmed.is_empty() && !comment_only {
            code_lines += 1;
        }
        if line.chars().count() > options.maximum_line_length {
            issues.push(line_issue(
                "go:S103",
                format!(
                    "Split this {0} characters long line (which is greater than {1} authorized).",
                    line.chars().count(),
                    options.maximum_line_length
                ),
                index,
                0,
                line.chars().count(),
            ));
        }
    }
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
    for (line_index, (line, original)) in code.lines().zip(source.lines()).enumerate() {
        check_mistyped_assignments(line_index, line, original, issues);
        check_statement_separator(line_index, line, original, issues);
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
                offset_issue(
                    key,
                    message,
                    source,
                    node.start_byte() + relative,
                    node.start_byte() + relative + tag.len(),
                )
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
    issues: &mut Vec<Issue>,
) {
    if let Some(column) = statement_separator(line) {
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

fn check_empty_block_comments(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        let comment = text(node, source);
        if node.kind() == "comment"
            && comment.starts_with("/*")
            && comment.ends_with("*/")
            && comment[2..comment.len() - 2].trim().is_empty()
        {
            issues.push(offset_issue(
                "go:S4663",
                "Remove this comment, it is empty.",
                source,
                node.start_byte(),
                node.end_byte(),
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

fn check_node(node: Node<'_>, source: &str, options: &AnalyzerOptions, issues: &mut Vec<Issue>) {
    if node.is_error() || node.is_missing() {
        issues.push(node_issue(
            "go:S2260",
            "A parsing error occurred in this file.",
            node,
            source,
        ));
        return;
    }
    match node.kind() {
        "function_declaration" | "method_declaration" => {
            check_function(node, source, options, issues);
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
        "expression_switch_statement" | "type_switch_statement" => {
            check_switch(node, source, options, issues);
        }
        "assignment_statement" => check_assignment(node, source, issues),
        "short_var_declaration" => {
            check_assignment(node, source, issues);
            check_variable_declaration(node, source, issues);
        }
        "var_spec" => check_variable_declaration(node, source, issues),
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
        if depth > options.maximum_nesting_depth {
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
    ) && ancestors(node).any(|ancestor| {
        matches!(
            ancestor.kind(),
            "expression_switch_statement" | "type_switch_statement"
        )
    }) {
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
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
) {
    if let Some(name) = node.child_by_field_name("name") {
        let value = text(name, source);
        if value != "_" && value.contains('_') {
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
        walk(parameters, &mut |child| {
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
    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    if !descendants(body).any(|child| {
        !matches!(child.kind(), "statement_list" | "block")
            && (child.kind() != "comment" || child.start_position().row > body.start_position().row)
    }) {
        issues.push(node_issue("go:S1186", "Add a nested comment explaining why this function is empty or complete the implementation.", body, source));
    }
    let lines = body
        .end_position()
        .row
        .saturating_sub(node.start_position().row)
        + 1;
    if lines > options.maximum_function_lines {
        issues.push(node_issue(
            "go:S138",
            format!("This function has {lines} lines of code, which is greater than the {0} authorized. Split it into smaller functions.", options.maximum_function_lines),
            node.child_by_field_name("name").unwrap_or(node),
            source,
        ));
    }
    let cognitive = cognitive_complexity(body) + usize::from(text(body, source).contains("&&"));
    if cognitive > options.maximum_cognitive_complexity {
        issues.push(node_issue(
            "go:S3776",
            format!("Refactor this method to reduce its Cognitive Complexity from {cognitive} to the {0} allowed.", options.maximum_cognitive_complexity),
            node.child_by_field_name("name").unwrap_or(node),
            source,
        ));
    }
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
        let mut cursor = node.walk();
        for name in node.children_by_field_name("name", &mut cursor) {
            check_local_name(name, source, issues);
        }
    } else if let Some(left) = node.child_by_field_name("left") {
        let mut cursor = left.walk();
        for name in left
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
        {
            check_local_name(name, source, issues);
        }
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
    let value = text(node, source).trim();
    if value.starts_with('!')
        && let Some(opposite) = opposite_comparison(value)
    {
        issues.push(node_issue(
            "go:S1940",
            format!("Use the opposite operator (\"{opposite}\") instead."),
            node,
            source,
        ));
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
    .find_map(|(operator, opposite)| value.contains(operator).then_some(opposite))
}

fn check_local_name(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let value = text(node, source);
    if value != "_" && value.contains('_') {
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
    if value != "_" && value.contains('_') {
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
    let operator = operator_text(node, left, right, source);
    check_identical_operands(left, right, source, issues);
    check_boolean_literal(left, right, &operator, source, issues);
    check_logical_complexity(node, &operator, source, options, issues);
    check_opposite_boolean_operator(node, right, &operator, source, issues);
}

fn check_identical_operands(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if normalized(text(left, source)) == normalized(text(right, source)) {
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
        let literal = if matches!(text(right, source), "true" | "false") {
            right
        } else {
            left
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
    if matches!(operator, "&&" | "||") && count > options.maximum_expression_complexity {
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
            let value = normalized(text(condition, source));
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
            branches.push((normalized_code(text(consequence, source)), consequence));
        }
        match item.child_by_field_name("alternative") {
            Some(alternative) if alternative.kind() == "if_statement" => {
                current = Some(alternative);
            }
            Some(alternative) => {
                branches.push((normalized_code(text(alternative, source)), alternative));
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
    if let Some((original, duplicate)) = duplicate_branch(branches) {
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
    walk(node, &mut |child| {
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
    });
    let has_default = descendants(node).any(|child| child.kind() == "default_case");
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
        && normalized(text(left, source)) == normalized(text(right, source))
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
        ) {
            let value = text(node, source).to_string();
            if value.len() > 3 {
                values.entry(value).or_default().push(node);
            }
        }
    });
    for nodes in values
        .values()
        .filter(|nodes| nodes.len() >= options.duplicate_string_threshold)
    {
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

fn check_duplicate_functions(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let mut bodies: HashMap<String, Node<'_>> = HashMap::new();
    walk(root, &mut |node| {
        if matches!(node.kind(), "function_declaration" | "method_declaration")
            && let Some(body) = node.child_by_field_name("body")
        {
            let value = normalized_code(text(body, source));
            if value != "{}"
                && let Some(original) = bodies.insert(value, node)
            {
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
            }
        }
    });
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

fn statement_separator(line: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("for ") || trimmed.starts_with("for{") {
        return None;
    }
    let bytes = line.as_bytes();
    let mut quoted = false;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' && quoted {
            escaped = true;
            continue;
        }
        if byte == b'"' {
            quoted = !quoted;
        }
        if byte == b';' && !quoted && line[index + 1..].trim().is_empty().not() {
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
    let raw_end = candidate
        .find([';', '}'])
        .map_or(line.len(), |relative| start + relative);
    let end = raw_end.saturating_sub(line[..raw_end].len() - line[..raw_end].trim_end().len());
    (start, end)
}

trait BoolNot {
    fn not(self) -> bool;
}
impl BoolNot for bool {
    fn not(self) -> bool {
        !self
    }
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

fn cognitive_complexity(node: Node<'_>) -> usize {
    let mut total = 0;
    let mut pending = vec![(node, 0_usize)];
    while let Some((current, nesting)) = pending.pop() {
        let control = matches!(
            current.kind(),
            "if_statement"
                | "for_statement"
                | "expression_switch_statement"
                | "type_switch_statement"
        );
        total += usize::from(control) * (nesting + 1);
        let next = nesting + usize::from(control);
        let mut cursor = current.walk();
        let mut children: Vec<_> = current.named_children(&mut cursor).collect();
        children.reverse();
        pending.extend(children.into_iter().map(|child| (child, next)));
    }
    total
}

fn control_depth(node: Node<'_>) -> usize {
    1 + ancestors(node)
        .filter(|parent| {
            matches!(
                parent.kind(),
                "if_statement"
                    | "for_statement"
                    | "expression_switch_statement"
                    | "type_switch_statement"
            )
        })
        .count()
}

fn logical_operator_count(node: Node<'_>, source: &str) -> usize {
    usize::from(node.kind() == "binary_expression")
        + descendants(node)
            .filter(|child| child.kind() == "binary_expression")
            .filter(|child| {
                let Some(left) = child.child_by_field_name("left") else {
                    return false;
                };
                let Some(right) = child.child_by_field_name("right") else {
                    return false;
                };
                matches!(
                    operator_text(*child, left, right, source).as_str(),
                    "&&" | "||"
                )
            })
            .count()
}

fn operator_text(node: Node<'_>, left: Node<'_>, right: Node<'_>, source: &str) -> String {
    source
        .get(left.end_byte()..right.start_byte())
        .unwrap_or_default()
        .trim()
        .to_string()
        .trim_matches(|character: char| character == '(' || character == ')')
        .trim()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .next()
        .unwrap_or_else(|| text(node, source))
        .to_string()
}

fn normalized(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn normalized_code(value: &str) -> String {
    value
        .lines()
        .map(|line| line.split("//").next().unwrap_or(line))
        .collect::<String>()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
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
        let mut cursor = current.walk();
        let mut children: Vec<_> = current.named_children(&mut cursor).collect();
        children.reverse();
        pending.extend(children);
    }
}

fn descendants(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    let mut nodes = Vec::new();
    let mut cursor = node.walk();
    let mut pending: Vec<_> = node.named_children(&mut cursor).collect();
    pending.reverse();
    while let Some(current) = pending.pop() {
        nodes.push(current);
        let mut cursor = current.walk();
        let mut children: Vec<_> = current.named_children(&mut cursor).collect();
        children.reverse();
        pending.extend(children);
    }
    nodes.into_iter()
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
        assert!(keys("package p\nfunc broken( {").contains(&"go:S2260".to_string()));
    }
}
