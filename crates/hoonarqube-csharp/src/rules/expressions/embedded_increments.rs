use super::support::{enclosing_callable, operator_of};
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S881 — increments and decrements stay standalone.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["prefix_unary_expression", "postfix_unary_expression"];
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &KINDS) {
        if is_error_tainted(unary) || !matches!(operator_of(unary), Some("++" | "--")) {
            continue;
        }
        let callable = enclosing_callable(unary).map(|owner| owner.id());
        let mixed = ancestors_of(unary)
            .take_while(|ancestor| {
                !matches!(ancestor.kind(), "expression_statement" | "for_statement")
                    && Some(ancestor.id()) != callable
            })
            .any(|ancestor| {
                matches!(
                    ancestor.kind(),
                    "binary_expression" | "conditional_expression" | "invocation_expression"
                )
            });
        if !mixed {
            continue;
        }
        let mut cursor = unary.walk();
        let operator = unary
            .children(&mut cursor)
            .find(|child| matches!(child.kind(), "++" | "--"))
            .unwrap_or(unary);
        let operation = if operator.kind() == "--" {
            "decrement"
        } else {
            "increment"
        };
        issues.push(issue(
            language,
            "S881",
            format!("Extract this {operation} operation into a dedicated statement."),
            range_of(operator, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};
    use serde_json::{Value, json};

    fn exact(source: &str) -> Vec<Value> {
        let report = analyze_default(source);
        with_key(&report, "csharpsquid:S881")
            .into_iter()
            .map(|i| serde_json::to_value(i).expect("complete issue"))
            .collect()
    }

    fn expected(line: u32, column: u32, decrement: bool) -> Value {
        let operation = if decrement { "decrement" } else { "increment" };
        json!({"rule_key":"csharpsquid:S881","message":format!("Extract this {operation} operation into a dedicated statement."),"range":{"start":{"line":line,"column":column},"end":{"line":line,"column":column+2}}})
    }

    #[test]
    fn s881_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    #[test]
    fn s881_standalone_and_for_clause_updates_stay_clean() {
        let report = analyze_default(
            "class C\n{\n    void M(int n)\n    {\n        int i = 0;\n        i++;\n        i--;\n        for (var j = 0; j < n; j++)\n        {\n            Step(i);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    #[test]
    fn s881_flags_embedded_prefix_and_postfix_updates() {
        let report = analyze_default(
            "class C\n{\n    int M(int i)\n    {\n        var first = i++ + 1;\n        Consume(--first);\n        return first;\n    }\n}\n",
        );
        let issues = with_key(&report, "csharpsquid:S881");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            serde_json::to_value(issues[0]).unwrap(),
            expected(5, 21, false)
        );
    }

    #[test]
    fn s881_spares_updates_used_only_as_assignment_values() {
        let report = analyze_default(
            "class C\n{\n    int M(int i)\n    {\n        var first = i++;\n        return --first;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    #[test]
    fn s881_does_not_mix_lambda_body_with_outer_invocation() {
        let report = analyze_default(
            "class C { void M(int i) { Consume(() => i++); Consume(delegate { return --i; }); } }",
        );
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    #[test]
    fn s881_matches_installed_call_index_and_arithmetic_boundaries() {
        let source = r"using System;
namespace Scope;
class Cases
{
    static int Take(int x) => x;
    static void Consume(int x) { }
    static void Lazy(Func<string> f) { }
    void M(string text, int[] values, int i)
    {
        var indexCall = text[--i].ToString();
        var postfixIndexCall = text[i++].ToString();
        var directIndex = values[--i];
        Consume(values[--i]);
        var indexComparison = values[--i] > 0;
        var parenthesizedIndex = text[(--i)].ToString();
        var arithmeticIndex = values[--i + 1];
        var callIndex = values[Take(--i)];
        var arithmeticIndexCall = text[i++ + 1].ToString();
        var ordinaryArithmetic = i++ + 1;
        Consume(--i);
        Lazy(() => text[--i].ToString());
        var discarded = i++;
        i++;
        for (var j = 0; j < 1; j++) { }
    }
}
";
        assert_eq!(
            exact(source),
            vec![
                expected(16, 37, true),
                expected(18, 40, false),
                expected(19, 34, false)
            ]
        );
    }

    #[test]
    fn s881_matches_installed_operator_kinds() {
        let source = r#"using System;
class Operators
{
    static int Take(int x) => x;
    int M(int i, int j, bool b)
    {
        var add = i++ + j;
        var subtract = i++ - j;
        var multiply = i++ * j;
        var divide = i++ / j;
        var remainder = i++ % j;
        var leftShift = i++ << j;
        var rightShift = i++ >> j;
        var unsignedShift = i++ >>> j;
        var bitAnd = i++ & j;
        var bitOr = i++ | j;
        var bitXor = i++ ^ j;
        var equal = i++ == j;
        var notEqual = i++ != j;
        var greater = i++ > j;
        var less = i++ < j;
        var greaterEqual = i++ >= j;
        var lessEqual = i++ <= j;
        var logicalAnd = i++ > 0 && b;
        var logicalOr = i++ > 0 || b;
        var condition = i++ > 0 ? 1 : 2;
        var conditionalArm = b ? i++ : j;
        var conditionalArithmetic = b ? i++ + 1 : j;
        var interpolation = $"{i++}";
        var cast = (long)i++;
        var negate = -(i++);
        var complement = ~(i++);
        i += j++;
        i = j++;
        Take(++i);
        return i;
    }
}
"#;
        assert_eq!(
            exact(source),
            vec![
                expected(7, 19, false),
                expected(8, 24, false),
                expected(9, 24, false),
                expected(10, 22, false),
                expected(11, 25, false),
                expected(28, 41, false)
            ]
        );
    }

    #[test]
    fn s881_preserves_arithmetic_through_expression_lambdas() {
        let source = r"using System;
class Barriers
{
    static int Take(int x) => x;
    static int Invoke(Func<int> f) => f();
    void M(string text, int[] values, int i)
    {
        var callThenArithmetic = Take(i++) + 1;
        var arithmeticArgument = Take(i++ + 1);
        var indexThenArithmetic = values[i++] + 1;
        var nestedArgumentArithmetic = values[Take(i++ + 1)];
        var conditionalArgument = Take(i++ > 0 ? 1 : 2);
        var conditionalIndex = values[i++ > 0 ? 1 : 2];
        var lambdaThenArithmetic = Invoke(() => i++) + 1;
        var nestedIndexThenArithmetic = values[values[i++]] + 1;
        var invokeThenIndex = values[Take(i++)] + 1;
        var explicitArithmetic = ((i++)) + 1;
        var lambdaIndex = Invoke(() => values[i++]) + 1;
    }
}
";
        assert_eq!(
            exact(source),
            vec![
                expected(8, 39, false),
                expected(9, 39, false),
                expected(10, 42, false),
                expected(11, 52, false),
                expected(14, 49, false),
                expected(15, 55, false),
                expected(16, 43, false),
                expected(17, 36, false),
                expected(18, 47, false)
            ]
        );
    }

    #[test]
    fn s881_preserves_unicode_crlf_exact_scalar_ranges() {
        let source = "// 😀 café\r\nusing System;\r\nclass Barriers\r\n{\r\n    static int Take(int x) => x;\r\n    static int Invoke(Func<int> f) => f();\r\n    void M(string text, int[] values, int i)\r\n    {\r\n        var callThenArithmetic = Take(i++) + 1;\r\n        var arithmeticArgument = Take(i++ + 1);\r\n        var indexThenArithmetic = values[i++] + 1;\r\n        var nestedArgumentArithmetic = values[Take(i++ + 1)];\r\n        var conditionalArgument = Take(i++ > 0 ? 1 : 2);\r\n        var conditionalIndex = values[i++ > 0 ? 1 : 2];\r\n        var lambdaThenArithmetic = Invoke(() => i++) + 1;\r\n        var nestedIndexThenArithmetic = values[values[i++]] + 1;\r\n        var invokeThenIndex = values[Take(i++)] + 1;\r\n        var explicitArithmetic = \"😀\".Length + ((i++)) + 1;\r\n        var lambdaIndex = Invoke(() => values[i++]) + 1;\r\n    }\r\n}\r\n";
        assert_eq!(
            exact(source),
            vec![
                expected(9, 39, false),
                expected(10, 39, false),
                expected(11, 42, false),
                expected(12, 52, false),
                expected(15, 49, false),
                expected(16, 55, false),
                expected(17, 43, false),
                expected(18, 49, false),
                expected(19, 47, false)
            ]
        );
    }

    #[test]
    fn s881_preserves_original_humanizer_nested_index_call() {
        let source = r"using System.Collections.Generic;
namespace Scope;
class Roman
{
    static readonly Dictionary<string, int> RomanNumerals = new();
    int M(string input, int i)
    {
        var digit = RomanNumerals[input[--i].ToString()];
        return digit;
    }
}
";
        assert!(exact(source).is_empty());
    }

    #[test]
    fn s881_preserves_error_tainted_source_without_false_clean_claim() {
        let source = "class Broken { void M( i++ + 1; }\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(tree.root_node().has_error());
        assert!(super::check(tree.root_node(), source, crate::CsLanguage::CSharp).is_empty());
    }
}
