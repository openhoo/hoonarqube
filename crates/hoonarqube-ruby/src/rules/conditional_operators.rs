//! `ruby:S1067` — expressions should not chain too many conditional
//! operators.
//!
//! Contract pinned against the live `SonarQube` 26.8 Community reference
//! (probe-verified on 2026-09-15, oracle: the pinned `rake` scan): every
//! `&&`, `||`, `and`, `or`, and `?:` inside an expression counts toward the
//! `max` parameter (catalog default 3), including operators nested inside
//! parentheses or call arguments. The finding anchors the whole flagged
//! expression — a condition, an assignment right-hand side, a call
//! argument — and reports once per outermost logical chain, so a chain
//! nested inside a larger chain is not double-counted at both levels.

use crate::AnalyzerOptions;
use crate::support::{SourceMap, node_text, walk};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Operators the reference counts as conditional operators.
fn is_conditional_operator(operator: &str) -> bool {
    matches!(operator, "&&" | "||" | "and" | "or")
}

/// The `binary` node's operator token.
fn operator_of<'a>(node: Node<'a>, source: &'a str) -> &'a str {
    node.child_by_field_name("operator")
        .map_or("", |operator| node_text(operator, source))
}

pub(crate) fn check(root: Node<'_>, source: &str, options: &AnalyzerOptions) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }
    let max = options.maximum_conditional_operators;
    let map = SourceMap::new(source);
    let mut issues = Vec::new();
    walk(root, |node| {
        if node.kind() != "binary" || !is_conditional_operator(operator_of(node, source)) {
            return;
        }
        // Only the outermost link of a logical chain reports; inner links of
        // the same chain are part of its count, not separate findings.
        if node.parent().is_some_and(|parent| {
            parent.kind() == "binary" && is_conditional_operator(operator_of(parent, source))
        }) {
            return;
        }
        let count = count_operators(node, source);
        if count > max {
            issues.push(Issue::new(
                "ruby:S1067",
                format!(
                    "Reduce the number of conditional operators ({count}) used in the expression (maximum allowed {max})."
                ),
                map.node_range(node),
            ));
        }
    });
    issues
}

/// Conditional-operator occurrences within an expression subtree, including
/// inside parentheses and call arguments.
fn count_operators(node: Node<'_>, source: &str) -> usize {
    let mut count = 0;
    walk(node, |descendant| {
        if descendant.kind() == "binary" && is_conditional_operator(operator_of(descendant, source))
        {
            count += 1;
        }
        // `a ? b : c` counts as one conditional operator.
        if descendant.kind() == "conditional" {
            count += 1;
        }
    });
    count
}

#[cfg(test)]
mod tests {
    use crate::rules::check_sonar_rules;
    use crate::{AnalyzerOptions, engine::parse_source};

    fn check(source: &str) -> Vec<hoonarqube_ir::Issue> {
        let tree = parse_source(source).expect("probe source parses");
        check_sonar_rules(&tree, source, &AnalyzerOptions::default())
            .into_iter()
            .filter(|issue| issue.rule_key == "ruby:S1067")
            .collect()
    }

    #[test]
    fn flags_expression_over_the_catalog_max() {
        let issues = check("def f(a, b, c, d, e)\n  if a && b && c && d && e\n    x\n  end\nend\n");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Reduce the number of conditional operators (4) used in the expression (maximum allowed 3)."
        );
        // The whole condition expression is the primary range.
        assert_eq!(issues[0].range.start.line, 2);
        assert_eq!(issues[0].range.start.column, 5);
    }

    #[test]
    fn counts_nested_parens_and_keyword_operators() {
        // a && (b || c) && (d || e): two && plus two || = 4.
        let issues =
            check("def f(a, b, c, d, e)\n  if a && (b || c) && (d || e)\n    x\n  end\nend\n");
        assert_eq!(issues.len(), 1);
        // `and`/`or` count too.
        let issues = check("def f(a, b, c, d, e)\n  z = a and b and c and d and e\nend\n");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("(4)"), "{}", issues[0].message);
    }

    #[test]
    fn silent_controls_match_the_reference() {
        for source in [
            // Exactly at the max: allowed.
            "def f(a, b, c, d)\n  if a && b && c && d\n    x\n  end\nend\n",
            // Bitwise operators are not conditional operators.
            "def f(a, b, c, d, e)\n  if a & b & c & d & e\n    x\n  end\nend\n",
            // Unary ! is not a conditional operator.
            "def f(a, b, c, d)\n  if !a && !b && !c && !d\n    x\n  end\nend\n",
        ] {
            assert!(check(source).is_empty(), "{source}");
        }
    }
}
