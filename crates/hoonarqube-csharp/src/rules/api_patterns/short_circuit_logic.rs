use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::dataflow::unary_operator;
use crate::rules::expressions::{binary_operands, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2178 — boolean conditions need short-circuit `&&`/`||`;
/// bitwise operators evaluate both sides and misread intent. Bound:
/// only condition positions, and only operands that read as booleans by
/// shape or naming convention.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || !matches!(operator_of(expression), Some("&" | "|"))
            || !condition_encloses(expression)
        {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        if looks_boolean_expression(left, source) && looks_boolean_expression(right, source) {
            issues.push(issue(
                language,
                "S2178",
                "Use '&&' or '||' for this boolean combination.",
                range_of(expression, source),
            ));
        }
    }
    issues
}

/// Whether this operand reads like a boolean: literals, comparisons,
/// negations, logical chains, or `Is*`/`Has*`/`Can*`/`Should*` names.
fn looks_boolean_expression(expression: Node<'_>, source: &str) -> bool {
    match expression.kind() {
        "boolean_literal" => true,
        "binary_expression" => matches!(
            operator_of(expression),
            Some("==" | "!=" | "<" | "<=" | ">" | ">=" | "&&" | "||")
        ),
        "prefix_unary_expression" => unary_operator(expression) == Some("!"),
        "identifier" => {
            let name = node_text(expression, source);
            ["Is", "Has", "Can", "Should"].iter().any(|prefix| {
                name.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
            })
        }
        _ => false,
    }
}

/// Whether this expression sits inside a control structure's condition.
fn condition_encloses(expression: Node<'_>) -> bool {
    let (start, end) = (expression.start_byte(), expression.end_byte());
    for ancestor in ancestors_of(expression) {
        match ancestor.kind() {
            "block"
            | "method_declaration"
            | "constructor_declaration"
            | "accessor_declaration"
            | "local_function_statement" => return false,
            "if_statement" | "while_statement" | "for_statement" | "do_statement" => {
                if let Some(condition) = ancestor.child_by_field_name("condition")
                    && condition.start_byte() <= start
                    && end <= condition.end_byte()
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}
