use super::support::binary_operator;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

/// csharpsquid:S1067 — one expression chains at most the tolerated number
/// of conditional and logical operators.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let (mut expressions, conditional_nodes) = conditional_components(root, source);
    let mut logical_roots = HashSet::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if conditional_nodes.contains(&expression.id())
            || is_error_tainted(expression)
            || !matches!(binary_operator(expression, source), "&&" | "||")
        {
            continue;
        }
        let component = component_root(expression, source);
        if is_error_tainted(component) || !logical_roots.insert(component.id()) {
            continue;
        }
        expressions.push((component, logical_operator_count(component, source)));
    }
    expressions
        .into_iter()
        .filter(|(_, count)| *count > options.maximum_logical_operators)
        .map(|(expression, count)| {
            issue(
                language,
                "S1067",
                format!(
                    "Reduce the number of conditional operators ({count}) used in the expression (maximum allowed {}).",
                    options.maximum_logical_operators
                ),
                range_of(expression, source),
            )
        })
        .collect()
}

/// Conditional-bearing components use bounded expression children.
fn conditional_components<'t>(
    root: Node<'t>,
    source: &str,
) -> (Vec<(Node<'t>, u32)>, HashSet<usize>) {
    let mut expressions = Vec::new();
    let mut included = HashSet::new();
    for conditional in collect_kinds(root, &["conditional_expression"]) {
        if included.contains(&conditional.id()) {
            continue;
        }
        let component = component_root(conditional, source);
        if is_error_tainted(component) {
            continue;
        }
        let count = conditional_operator_count(component, source, &mut included);
        expressions.push((component, count));
    }
    (expressions, included)
}

fn component_root<'t>(mut expression: Node<'t>, source: &str) -> Node<'t> {
    while let Some(parent) = expression
        .parent()
        .filter(|parent| is_component_expression(*parent, source))
    {
        expression = parent;
    }
    expression
}

/// Calls, casts, lambdas and other unsupported syntax stop this traversal even
/// when they contain conditional or logical descendants of their own.
fn conditional_operator_count(
    expression: Node<'_>,
    source: &str,
    included: &mut HashSet<usize>,
) -> u32 {
    let mut count = 0_u32;
    let mut pending = vec![expression];
    while let Some(node) = pending.pop() {
        if !is_component_expression(node, source) {
            continue;
        }
        included.insert(node.id());
        if node.kind() == "conditional_expression"
            || (node.kind() == "binary_expression"
                && matches!(binary_operator(node, source), "&&" | "||"))
        {
            count = count.saturating_add(1);
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    count
}

fn is_component_expression(expression: Node<'_>, source: &str) -> bool {
    match expression.kind() {
        "conditional_expression" | "parenthesized_expression" => true,
        "prefix_unary_expression" => binary_operator(expression, source) == "!",
        "binary_expression" => matches!(
            binary_operator(expression, source),
            "&&" | "||"
                | "??"
                | "|"
                | "^"
                | "&"
                | "=="
                | "!="
                | "<"
                | "<="
                | ">"
                | ">="
                | "<<"
                | ">>"
                | ">>>"
                | "+"
                | "-"
                | "*"
                | "/"
                | "%"
        ),
        _ => false,
    }
}

/// Logical-operator occurrences within a pure-logical component subtree,
/// including descendants inside unsupported expressions.
fn logical_operator_count(expression: Node<'_>, source: &str) -> u32 {
    to_u32(
        collect_kinds(expression, &["binary_expression"])
            .iter()
            .filter(|operand| matches!(binary_operator(**operand, source), "&&" | "||"))
            .count(),
    )
}

#[cfg(test)]
mod tests {
    use crate::{AnalyzerOptions, CsLanguage};
    use hoonarqube_ir::{Issue, Pos, Range};
    use std::path::PathBuf;

    const KEY: &str = "csharpsquid:S1067";
    const FOUR: &str = "(a ? 1 : 0) + (b ? 1 : 0) + (c ? 1 : 0) + (d ? 1 : 0)";

    fn source(expression: &str) -> String {
        format!(
            "class C {{ object M(bool a, bool b, bool c, bool d, bool e, bool f, bool g, bool h, bool i) => {expression}; }}"
        )
    }

    fn targets(source: &str, maximum: u32) -> Vec<Issue> {
        crate::analyze(
            PathBuf::from("Control.cs"),
            source,
            CsLanguage::CSharp,
            &AnalyzerOptions {
                maximum_logical_operators: maximum,
                ..AnalyzerOptions::default()
            },
        )
        .issues
        .into_iter()
        .filter(|issue| issue.rule_key == KEY)
        .collect()
    }

    fn position(source: &str, offset: usize) -> Pos {
        let prefix = &source[..offset];
        Pos {
            line: u32::try_from(prefix.bytes().filter(|&byte| byte == b'\n').count() + 1)
                .expect("fixture line"),
            column: u32::try_from(prefix.rsplit('\n').next().unwrap().chars().count())
                .expect("fixture column"),
        }
    }

    fn expected(source: &str, fragment: &str, count: u32, maximum: u32) -> Issue {
        let start = source
            .find(fragment)
            .expect("independent expected source span");
        Issue::new(
            KEY,
            format!(
                "Reduce the number of conditional operators ({count}) used in the expression (maximum allowed {maximum})."
            ),
            Range {
                start: position(source, start),
                end: position(source, start + fragment.len()),
            },
        )
    }

    fn one(expression: &str, count: u32) {
        let source = source(expression);
        assert_eq!(
            targets(&source, 3),
            vec![expected(&source, expression, count, 3)]
        );
    }

    #[test]
    fn s1067_conditional_counts_four_ternaries_in_one_additive_expression() {
        one(FOUR, 4);
    }

    #[test]
    fn s1067_conditional_keeps_three_ternaries_clean_at_default_threshold() {
        assert!(targets(&source("(a ? 1 : 0) + (b ? 1 : 0) + (c ? 1 : 0)"), 3).is_empty());
    }

    #[test]
    fn s1067_conditional_uses_configured_maximum_in_count_and_message() {
        let four = source(FOUR);
        assert!(targets(&four, 4).is_empty());
        assert_eq!(targets(&four, 2), vec![expected(&four, FOUR, 4, 2)]);
        let single = source("a ? 1 : 0");
        assert!(targets(&single, 1).is_empty());
        assert_eq!(
            targets(&single, 0),
            vec![expected(&single, "a ? 1 : 0", 1, 0)]
        );
    }

    #[test]
    fn s1067_conditional_counts_mixed_logical_operators_on_complete_ternary() {
        one("a && b || c ? d && e : false", 4);
        one("a && b && c && d && e ? a : b", 5);
    }

    #[test]
    fn s1067_conditional_combines_directly_nested_condition() {
        one("(a ? b : c) ? (d ? 1 : 0) : (e ? 1 : 0)", 4);
    }

    #[test]
    fn s1067_conditional_combines_directly_nested_true_branch() {
        one("a ? b ? 1 : c ? 2 : 3 : d ? 4 : 5", 4);
    }

    #[test]
    fn s1067_conditional_combines_directly_nested_false_branch() {
        one("a ? 1 : b ? 2 : c ? 3 : d ? 4 : 5", 4);
    }

    #[test]
    fn s1067_conditional_reports_outermost_transparent_parentheses() {
        one(
            "(((a ? 1 : 0) + (b ? 1 : 0)) + ((c ? 1 : 0) + (d ? 1 : 0)))",
            4,
        );
        one("(a && b || c) ? (d && e) : false", 4);
    }

    #[test]
    fn s1067_conditional_crosses_only_reference_transparent_binary_operators() {
        for operator in [
            "+", "-", "*", "/", "%", "<<", ">>", ">>>", "|", "&", "^", "==", "!=", "<", "<=", ">",
            ">=",
        ] {
            one(
                &format!("((a ? 1 : 0) + (b ? 1 : 0)) {operator} ((c ? 1 : 0) + (d ? 1 : 0))"),
                4,
            );
        }
        one(
            "((a ? (int?)1 : null) + (b ? (int?)1 : null)) ?? ((c ? (int?)1 : null) + (d ? (int?)1 : null))",
            4,
        );
    }

    #[test]
    fn s1067_conditional_transparent_logical_not_does_not_increase_count() {
        one("!((a ? b : c) && (d ? e : f) && (g ? h : i))", 5);
    }

    #[test]
    fn s1067_conditional_invocation_arguments_are_separate_components() {
        let expression = format!("a ? F({FOUR}) : 0");
        let source = source(&expression);
        assert_eq!(targets(&source, 3), vec![expected(&source, FOUR, 4, 3)]);
        assert!(
            targets(
                &self::source("F(a ? 1 : 0, b ? 1 : 0, c ? 1 : 0, d ? 1 : 0)"),
                3
            )
            .is_empty()
        );
    }

    #[test]
    fn s1067_conditional_lambda_body_is_a_separate_component() {
        let expression = format!("a ? F(() => {FOUR}) : 0");
        let source = source(&expression);
        assert_eq!(targets(&source, 3), vec![expected(&source, FOUR, 4, 3)]);
        assert!(
            targets(
                &self::source("a && b ? F(() => (c ? 1 : 0) + (d ? 1 : 0)) : 0"),
                3
            )
            .is_empty()
        );
    }

    #[test]
    fn s1067_conditional_cast_stops_the_outer_component() {
        let inner = format!("({FOUR})");
        let expression = format!("a ? (int){inner} : 0");
        let source = source(&expression);
        assert_eq!(targets(&source, 3), vec![expected(&source, &inner, 4, 3)]);
    }

    #[test]
    fn s1067_conditional_preserves_one_complete_pure_logical_component() {
        one("a || (b && c && d && e && f)", 5);
    }

    #[test]
    fn s1067_conditional_preserves_original_logical_positive_and_clean_controls() {
        one("a && b && c && d && e", 4);
        assert!(targets(&source("a && b && c && d"), 3).is_empty());
        assert!(targets(&source("(a && b) || (c && d)"), 3).is_empty());
    }

    #[test]
    fn s1067_conditional_ignores_comment_and_string_operator_spellings() {
        assert!(targets(&source("a ? \"&& || ? : && ? :\" : \"? :\""), 3).is_empty());
        let expression = "a && b && c && d && e /* ? : && || */";
        let source = source(expression);
        let span = "a && b && c && d && e";
        assert_eq!(targets(&source, 3), vec![expected(&source, span, 4, 3)]);
    }

    #[test]
    fn s1067_conditional_retains_ranges_in_lf_crlf_and_non_ascii_source() {
        let expression = "(a ? \"一\" : \"\") + (b ? \"二\" : \"\")\n + (c ? \"三\" : \"\") + (d ? \"四\" : \"\")";
        for newline in ["\n", "\r\n"] {
            let expression = expression.replace('\n', newline);
            let source = format!(
                "// header{newline}class C {{ /* 😀 */ object M(bool a, bool b, bool c, bool d) => {expression}; }}{newline}"
            );
            assert_eq!(
                targets(&source, 3),
                vec![expected(&source, &expression, 4, 3)]
            );
        }
    }

    #[test]
    fn s1067_conditional_keeps_malformed_trees_out_of_detector_output() {
        for source in [
            "class C { int M(bool a) => a ? 1 : ; }",
            "class C { int M(bool a) => (a ? 1 : 0) + (a ? : 0) + (a ? 1 : 0) + (a ? 1 : 0); }",
        ] {
            assert!(targets(source, 0).is_empty());
        }
    }

    #[test]
    fn s1067_logical_parenthesized_component_has_no_inner_duplicate() {
        one("a || (b && c && d && e && f)", 5);
    }

    #[test]
    fn s1067_logical_root_includes_all_transparent_parentheses() {
        one("(a || (b && c && d && e && f))", 5);
        one("(((a && b && c && d && e)))", 4);
    }

    #[test]
    fn s1067_logical_root_includes_logical_negation() {
        one("!(a || (b && c && d && e && f))", 5);
    }

    #[test]
    fn s1067_logical_root_includes_the_comparison_expression() {
        one("(a && b && c && d && e) == f", 4);
    }

    #[test]
    fn s1067_logical_combines_chains_joined_by_equality_and_bitwise_operators() {
        for expression in [
            "(a && b && c) == (d && e && f)",
            "(a && b && c) & (d && e && f)",
            "!((a && b && c) == (d && e && f))",
            "((a && b && c) & (d && e)) || f",
        ] {
            one(expression, 4);
        }
    }

    #[test]
    fn s1067_logical_component_uses_configured_maximum_and_message() {
        let expression = "(a || (b && c && d && e && f))";
        let source = source(expression);
        assert!(targets(&source, 5).is_empty());
        assert_eq!(
            targets(&source, 4),
            vec![expected(&source, expression, 5, 4)]
        );
        assert_eq!(
            targets(&source, 2),
            vec![expected(&source, expression, 5, 2)]
        );
        let single = self::source("(a && b)");
        assert!(targets(&single, 1).is_empty());
        assert_eq!(
            targets(&single, 0),
            vec![expected(&single, "(a && b)", 1, 0)]
        );
    }

    #[test]
    fn s1067_logical_below_threshold_and_lexical_decoys_remain_clean() {
        for expression in [
            "a && b && c && d",
            "(a || (b && c && d))",
            "!(a && b && c && d)",
            "(a && b) == (c && d)",
            "(a && b && c) == d",
            r#""&& || ? : && ||" != """#,
        ] {
            assert!(targets(&source(expression), 3).is_empty(), "{expression}");
        }
    }

    #[test]
    fn s1067_logical_invocation_arguments_remain_separate_components() {
        let left = "a && b && c && d && e";
        let right = "b && c && d && e && f";
        let source = source(&format!("F({left}) | F({right})"));
        assert_eq!(
            targets(&source, 3),
            vec![
                expected(&source, left, 4, 3),
                expected(&source, right, 4, 3)
            ]
        );
    }

    #[test]
    fn s1067_logical_preserves_separate_opaque_call_counting_residual() {
        let outer = "a || F(b && c && d && e && f)";
        let source = source(outer);
        assert_eq!(
            targets(&source, 3),
            vec![
                expected(&source, outer, 5, 3),
                expected(&source, "b && c && d && e && f", 4, 3)
            ]
        );
        let outer = "F(a && b && c) || F(d && e && f)";
        let source = self::source(outer);
        assert_eq!(targets(&source, 3), vec![expected(&source, outer, 5, 3)]);
    }

    #[test]
    fn s1067_logical_lambda_and_cast_inner_roots_keep_complete_parentheses() {
        for outer in [
            "a || F(() => (b && c && d && e && f))",
            "a || (bool)(b && c && d && e && f)",
        ] {
            let source = source(outer);
            assert_eq!(
                targets(&source, 3),
                vec![
                    expected(&source, outer, 5, 3),
                    expected(&source, "(b && c && d && e && f)", 4, 3)
                ]
            );
        }
    }

    #[test]
    fn s1067_logical_romanian_shape_retains_only_matching_outer_object() {
        let expression = "a && (!words.EndsWith(\"zece\")\n && (words.EndsWith(\"a\") || words.EndsWith(\"ă\")\n || words.EndsWith(\"e\") || words.EndsWith(\"i\")))";
        one(expression, 5);
    }

    #[test]
    fn s1067_logical_complete_spans_preserve_unicode_and_line_endings() {
        for newline in ["\n", "\r\n"] {
            let expression = format!("!(a ||{newline} (b && c && d && e && f))");
            let source = format!(
                "\u{feff}// header{newline}class C {{ /* 😀 */ bool M(bool a, bool b, bool c, bool d, bool e, bool f) => {expression}; }}{newline}"
            );
            assert_eq!(
                targets(&source, 3),
                vec![expected(&source, &expression, 5, 3)]
            );
        }
    }

    #[test]
    fn s1067_logical_malformed_components_do_not_produce_clean_findings() {
        for source in [
            "class C { bool M(bool a) => !(a && ; }",
            "class C { bool M(bool a) => a || (a && ; }",
        ] {
            assert!(targets(source, 0).is_empty());
        }
    }
}
