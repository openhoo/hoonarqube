//! `ruby:S1764` — identical sub-expressions on both sides of a binary
//! operator.
//! Contract pinned against the live `SonarQube` 26.8 Community reference
//! (probe-verified on 2026-09-15 against a dedicated scan project, oracle:
//! the pinned `rake` scan): when both operands of `==`, `!=`, `<`, `<=`,
//! `>`, `>=`, `-`, `/`, `&`, `&&`, or `||` are the same expression, the
//! right operand is flagged and the left becomes a secondary location.
//! Everything else stays silent — `+`, `*`, `**`, `%`, `|`, `^`, `<<`,
//! `>>`, `<=>`, `===`, `=~`, `!~`, and the keyword forms `and`/`or` —
//! because `a + a`-style expressions are routinely intentional. Identical
//! literal operands (`1 == 1`, `"s" == "s"`) are excluded. Operands compare
//! by canonical form (node kinds plus token text), so `a+1 == a + 1` still
//! matches while `a == b` stays clean.

use crate::support::{SourceMap, node_text, walk};
use hoonarqube_ir::{FlowLocation, Issue};
use tree_sitter::Node;

/// Operators whose identical operands betray a bug rather than an idiom.
const FLAGGED_OPERATORS: &[&str] = &["==", "!=", "<", "<=", ">", ">=", "-", "/", "&", "&&", "||"];

pub(crate) fn check(root: Node<'_>, source: &str) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }
    let map = SourceMap::new(source);
    let mut issues = Vec::new();
    walk(root, |node| {
        if node.kind() != "binary" {
            return;
        }
        let operator = node
            .child_by_field_name("operator")
            .map_or("", |token| node_text(token, source));
        if !FLAGGED_OPERATORS.contains(&operator) {
            return;
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        if canonical_code(left, source) != canonical_code(right, source)
            || (is_literal(left) && is_literal(right))
        {
            return;
        }
        issues.push(
            Issue::new(
                "ruby:S1764",
                "Correct one of the identical sub-expressions on both sides this operator",
                map.node_range(right),
            )
            .with_flow(vec![FlowLocation::in_primary_file(
                "",
                map.node_range(left),
            )]),
        );
    });
    issues
}

/// Literal operands the reference excludes: `1 == 1` or `"s" == "s"` is a
/// constant expression, not a bug.
fn is_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer"
            | "float"
            | "string"
            | "simple_symbol"
            | "hash_key_symbol"
            | "true"
            | "false"
            | "nil"
            | "array"
            | "hash"
            | "regex"
            | "complex"
            | "rational"
            | "character"
    )
}

/// Whitespace- and comment-insensitive structural fingerprint of an
/// expression: every node's kind and leaf text in source order.
fn canonical_code(node: Node<'_>, source: &str) -> String {
    let mut value = String::new();
    walk(node, |current| {
        if current.kind() == "comment" {
            return;
        }
        if current.child_count() == 0 {
            value.push_str(current.kind());
            value.push('\0');
            value.push_str(node_text(current, source));
            value.push('\0');
        }
    });
    value
}

#[cfg(test)]
mod tests {
    use crate::rules::check_sonar_rules;
    use crate::{AnalyzerOptions, engine::parse_source};

    fn check(source: &str) -> Vec<hoonarqube_ir::Issue> {
        let tree = parse_source(source).expect("probe source parses");
        check_sonar_rules(&tree, source, &AnalyzerOptions::default())
            .into_iter()
            .filter(|issue| issue.rule_key == "ruby:S1764")
            .collect()
    }

    #[test]
    fn flags_identical_operands_with_reference_message_and_flow() {
        let issues = check("def f(t1)\n  assert t1 == t1\nend\n");
        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(
            issue.message,
            "Correct one of the identical sub-expressions on both sides this operator"
        );
        // Primary is the right operand: line 2, columns 15..17.
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(issue.range.start.column, 15);
        assert_eq!(issue.range.end.column, 17);
        // The left operand is the single secondary location.
        assert_eq!(issue.flows.len(), 1);
        assert_eq!(issue.flows[0].locations.len(), 1);
        assert_eq!(issue.flows[0].locations[0].range.start.column, 9);
    }

    #[test]
    fn whitespace_differences_still_match() {
        let issues = check("def f(a)\n  x = a+1 == a + 1\nend\n");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn probe_verified_operator_set() {
        // Every operator the reference flagged on the probe corpus.
        let flagged = check(
            "def f(a)\n  x1 = a == a\n  x2 = a != a\n  x3 = a < a\n  x4 = a <= a\n  x5 = a > a\n  x6 = a >= a\n  x7 = a - a\n  x8 = a / a\n  x9 = a & a\n  x10 = a && a\n  x11 = a || a\nend\n",
        );
        assert_eq!(flagged.len(), 11);
    }

    #[test]
    fn silent_controls_match_the_reference() {
        for source in [
            // Distinct operands.
            "def f(a, b)\n  x = a == b\n  y = a - b\nend\n",
            // Additive, multiplicative, and other unflagged operators.
            "def f(a)\n  x = a + a\n  y = a * a\n  z = a ** a\n  w = a % a\n  v = a | a\n  u = a ^ a\n  t = a << a\n  s = a >> a\n  r = a <=> a\n  q = a === a\n  p = a =~ a\n  o = a !~ a\n  n = a and a\n  m = a or a\nend\n",
            // Identical literals are constant expressions, not bugs.
            "def f\n  x = 1 == 1\n  y = \"s\" == \"s\"\nend\n",
        ] {
            assert!(check(source).is_empty(), "{source}");
        }
    }
}
