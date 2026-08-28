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
    check_textual(source, &mut issues);
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

fn check_textual(source: &str, issues: &mut Vec<Issue>) {
    let bytes = source.as_bytes();
    for (line_index, line) in source.lines().enumerate() {
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
            if let Some(column) = line.find(tag) {
                issues.push(line_issue(
                    key,
                    message,
                    line_index,
                    column,
                    column + tag.len(),
                ));
            }
        }
        for token in ["=+", "=-"] {
            let mut start = 0;
            while let Some(relative) = line[start..].find(token) {
                let column = start + relative;
                issues.push(line_issue(
                    "go:S2757",
                    if token == "=+" {
                        "Was \"+=\" meant instead?"
                    } else {
                        "Was \"-=\" meant instead?"
                    },
                    line_index,
                    column,
                    column + 2,
                ));
                start = column + 2;
            }
        }
        if let Some(column) = statement_separator(line) {
            let (start, end) = statement_after(line, column);
            issues.push(line_issue(
                "go:S122",
                "Reformat the code to have only one statement per line.",
                line_index,
                start,
                end,
            ));
        }
    }

    let mut offset = 0_usize;
    while let Some(relative) = source[offset..].find("/*") {
        let start = offset + relative;
        let Some(end_relative) = source[start + 2..].find("*/") else {
            break;
        };
        let end = start + 2 + end_relative + 2;
        if source[start + 2..end - 2].trim().is_empty() {
            issues.push(offset_issue(
                "go:S4663",
                "Remove this comment, it is empty.",
                source,
                start,
                end,
            ));
        }
        offset = end;
    }

    // Keep the byte slice used: source can contain arbitrary UTF-8 but all
    // textual searches above are on valid char boundaries.
    let _ = bytes;
}

fn check_node(node: Node<'_>, source: &str, options: &AnalyzerOptions, issues: &mut Vec<Issue>) {
    if node.is_error() || node.is_missing() {
        issues.push(node_issue(
            "go:S2260",
            "A parsing error occurred in this file.",
            node,
        ));
        return;
    }
    match node.kind() {
        "function_declaration" | "method_declaration" => {
            check_function(node, source, options, issues);
        }
        "block" => check_block(node, source, issues),
        "statement_list" => check_statements(node, issues),
        "parenthesized_expression" => {
            if first_named(node).is_some_and(|child| child.kind() == "parenthesized_expression") {
                issues.push(keyword_issue(
                    "go:S1110",
                    "Remove these useless parentheses.",
                    node,
                    1,
                    1,
                ));
            }
        }
        "binary_expression" => check_binary(node, source, options, issues),
        "unary_expression" => check_unary(node, source, issues),
        "if_statement" => check_if(node, source, issues),
        "expression_switch_statement" | "type_switch_statement" => {
            check_switch(node, source, options, issues);
        }
        "assignment_statement" | "short_var_declaration" => check_assignment(node, source, issues),
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
        issues.push(node_issue("go:S1186", "Add a nested comment explaining why this function is empty or complete the implementation.", body));
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
        ));
    }
    let cognitive = cognitive_complexity(body) + usize::from(text(body, source).contains("&&"));
    if cognitive > options.maximum_cognitive_complexity {
        issues.push(node_issue(
            "go:S3776",
            format!("Refactor this method to reduce its Cognitive Complexity from {cognitive} to the {0} allowed.", options.maximum_cognitive_complexity),
            node.child_by_field_name("name").unwrap_or(node),
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
        ));
    }
    walk(node, &mut |child| {
        if matches!(child.kind(), "short_var_declaration" | "var_spec")
            && let Some(name) = first_identifier(child)
        {
            check_local_name(name, source, issues);
        }
    });
}

fn check_statements(node: Node<'_>, issues: &mut Vec<Issue>) {
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
        && ["==", "!=", "<", ">", "<=", ">="]
            .iter()
            .any(|operator| value.contains(operator))
    {
        let opposite = if value.contains("==") {
            "!="
        } else if value.contains("!=") {
            "=="
        } else if value.contains("<=") {
            ">"
        } else if value.contains(">=") {
            "<"
        } else if value.contains('<') {
            ">="
        } else {
            "<="
        };
        issues.push(node_issue(
            "go:S1940",
            format!("Use the opposite operator (\"{opposite}\") instead."),
            node,
        ));
    }
}

fn check_local_name(node: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    let value = text(node, source);
    if value != "_" && value.contains('_') {
        issues.push(node_issue(
            "go:S117",
            "Rename this local variable to match the regular expression \"^(_|[a-zA-Z0-9]+)$\".",
            node,
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
    if normalized(text(left, source)) == normalized(text(right, source)) {
        issues.push(node_issue(
            "go:S1764",
            "Correct one of the identical sub-expressions on both sides of this operator.",
            right,
        ));
    }
    if (matches!(text(right, source), "true" | "false")
        || matches!(text(left, source), "true" | "false"))
        && matches!(operator.as_str(), "&&" | "||" | "==" | "!=")
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
        ));
    }
    if matches!(operator.as_str(), "&&" | "||")
        && logical_operator_count(node, source) > options.maximum_expression_complexity
    {
        issues.push(node_issue(
            "go:S1067",
            format!("Reduce the number of conditional operators ({}) used in the expression (maximum allowed {}).", logical_operator_count(node, source), options.maximum_expression_complexity),
            node,
        ));
    }
    if matches!(
        (operator.as_str(), text(right, source)),
        ("==", "false") | ("!=", "true")
    ) {
        issues.push(node_issue(
            "go:S1940",
            "Use the opposite operator instead.",
            node,
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
        ));
    }
    if node
        .parent()
        .is_none_or(|parent| parent.kind() != "if_statement")
    {
        let mut conditions: Vec<(String, u32)> = Vec::new();
        let mut branches = Vec::new();
        let mut current = Some(node);
        let mut last_if = node;
        let mut ends_with_else = false;
        while let Some(item) = current {
            last_if = item;
            if let Some(condition) = item.child_by_field_name("condition") {
                let value = normalized(text(condition, source));
                if let Some((_, line)) = conditions.iter().find(|(previous, _)| previous == &value)
                {
                    issues.push(node_issue(
                        "go:S1862",
                        format!("This condition duplicates the one on line {line}."),
                        condition,
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
        if conditions.len() > 1 && !ends_with_else {
            let start = last_if.start_position();
            let offset = start.column.saturating_sub(5);
            issues.push(line_issue(
                "go:S126",
                "Add the missing \"else\" clause.",
                start.row,
                offset,
                offset + 7,
            ));
        }
        if let Some((original, duplicate)) = duplicate_branch(&branches) {
            issues.push(node_issue(
                "go:S1871",
                format!(
                    "This branch's code block is the same as the block for the branch on line {}.",
                    original.start_position().row + 1
                ),
                duplicate,
            ));
        }
        if ends_with_else
            && branches.len() > 1
            && branches.iter().all(|branch| branch.0 == branches[0].0)
        {
            issues.push(node_issue("go:S3923", "Remove this conditional structure or edit its code blocks so that they're not all the same.", node));
        }
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
    fn visit(node: Node<'_>, nesting: usize) -> usize {
        let control = matches!(
            node.kind(),
            "if_statement"
                | "for_statement"
                | "expression_switch_statement"
                | "type_switch_statement"
        );
        let here = usize::from(control) * (nesting + 1);
        let next = nesting + usize::from(control);
        let mut total = here;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            total += visit(child, next);
        }
        total
    }
    visit(node, 0)
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

fn first_identifier(node: Node<'_>) -> Option<Node<'_>> {
    descendants(node).find(|child| child.kind() == "identifier")
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

fn descendants(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    let mut nodes = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        nodes.push(child);
        nodes.extend(descendants(child));
    }
    nodes.into_iter()
}

fn ancestors(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    std::iter::successors(node.parent(), tree_sitter::Node::parent)
}

fn node_issue(key: &str, message: impl Into<String>, node: Node<'_>) -> Issue {
    Issue::new(
        key,
        message,
        point_range(node.start_position(), node.end_position()),
    )
}

fn keyword_issue(
    key: &str,
    message: impl Into<String>,
    node: Node<'_>,
    offset: usize,
    length: usize,
) -> Issue {
    let start = node.start_position();
    line_issue(
        key,
        message,
        start.row,
        start.column + offset,
        start.column + offset + length,
    )
}

fn header_issue(key: &str, message: impl Into<String>, node: Node<'_>, source: &str) -> Issue {
    let start = node.start_position();
    let first_line = text(node, source).lines().next().unwrap_or_default();
    let length = first_line.find(':').map_or(4, |column| column + 1);
    line_issue(key, message, start.row, start.column, start.column + length)
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
            .map_or(before.len(), |(_, tail)| tail.len());
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
    fn parser_errors_are_reported_without_panicking() {
        assert!(keys("package p\nfunc broken( {").contains(&"go:S2260".to_string()));
    }
}
