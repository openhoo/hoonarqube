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
}
