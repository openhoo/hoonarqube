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
            let mut cursor = expression.walk();
            let operator = expression
                .children(&mut cursor)
                .find(|child| matches!(child.kind(), "&" | "|"))
                .unwrap_or(expression);
            let replacement = if operator.kind() == "&" { "&&" } else { "||" };
            issues.push(issue(
                language,
                "S2178",
                format!("Correct this '{}' to '{replacement}'.", operator.kind()),
                range_of(operator, source),
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    // These full objects are frozen from unchanged CLI controls, with only
    // independently selected runtime message replacements. Unknown stays short.
    const CONTROLS: &[(&str, &str, &str, &str, &str)] = &[
        (
            r####"runtime"####,
            r####"int_==_&"####,
            r####"class C {  bool M(int n) {  if (true & n == 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_==_|"####,
            r####"class C {  bool M(int n) {  if (true | n == 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_!=_&"####,
            r####"class C {  bool M(int n) {  if (true & n != 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_!=_|"####,
            r####"class C {  bool M(int n) {  if (true | n != 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_<_&"####,
            r####"class C {  bool M(int n) {  if (true & n < 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_<_|"####,
            r####"class C {  bool M(int n) {  if (true | n < 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_<=_&"####,
            r####"class C {  bool M(int n) {  if (true & n <= 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_<=_|"####,
            r####"class C {  bool M(int n) {  if (true | n <= 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_>_&"####,
            r####"class C {  bool M(int n) {  if (true & n > 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_>_|"####,
            r####"class C {  bool M(int n) {  if (true | n > 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_>=_&"####,
            r####"class C {  bool M(int n) {  if (true & n >= 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"int_>=_|"####,
            r####"class C {  bool M(int n) {  if (true | n >= 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"constant"####,
            r####"long"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1L < 2L) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"uint"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1U < 2U) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"ulong"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1UL < 2UL) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"float"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1F < 2F) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"double"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1.0 < 2.0) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"decimal"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1M < 2M) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"char"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 'a' == 'b') return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"string"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & "a" == "b") return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"arithmetic"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1 + 2 < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"runtime_arithmetic"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & n + 1 < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"local_const"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & limit < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"field_const"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & Limit < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"enum"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & E.One == E.Two) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"maxvalue"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & int.MaxValue > 0) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"const_negation"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & !flag) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"nameof"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & nameof(n) == "n") return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"cast"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & (int)n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"checked"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & checked(n + 1) < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"unchecked"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & unchecked(n + 1) < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"default"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & default(int) == 0) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"bool_literal"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & !true) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"int_literal"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1 < 2) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"bool_equality"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & true != false) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"constant"####,
            r####"null_equality"####,
            r####"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & null == null) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"humanizer_fourth_declarator"####,
            r####"class C {  bool M() { int seconds = 0, minutes = 1, hours = 2, days = 30; days += 1; if (true & days <= 31) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":94},"end":{"line":1,"column":95}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":107},"end":{"line":1,"column":108}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"literal_local"####,
            r####"class C {  bool M() { int n = 2; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":42},"end":{"line":1,"column":43}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"call_initializer"####,
            r####"class C { int Read() { return 2; } bool M() { int n = Read(); n++; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":76},"end":{"line":1,"column":77}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":89},"end":{"line":1,"column":90}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"member_initializer"####,
            r####"class C { int Value; bool M() { int n = Value; n = 3; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":63},"end":{"line":1,"column":64}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":76},"end":{"line":1,"column":77}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"bool_local"####,
            r####"class C {  bool M() { bool flag = true; if (true & !flag) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":49},"end":{"line":1,"column":50}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":62},"end":{"line":1,"column":63}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"optional_parameter"####,
            r####"class C {  bool M(int n = 2) {  if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"escaped_parameter"####,
            r####"class C {  bool M(int @value) {  if (true & @value < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":42},"end":{"line":1,"column":43}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"escaped_local"####,
            r####"class C {  bool M() { int @value = 2; if (true & @value < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":47},"end":{"line":1,"column":48}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":60},"end":{"line":1,"column":61}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"bool_parameter_equality"####,
            r####"class C {  bool M(bool flag) {  if (true & flag == false) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"comparison_negation"####,
            r####"class C {  bool M(int n) {  if (true & !(n < 4)) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"bool_parameter_negation"####,
            r####"class C {  bool M(bool flag) {  if (true & !flag) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"declared_call"####,
            r####"class C { bool ReadFlag() { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":64},"end":{"line":1,"column":65}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":77},"end":{"line":1,"column":78}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"escaped_call"####,
            r####"class C { bool @ReadFlag() { return true; } bool M() {  if (true & !@ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":65},"end":{"line":1,"column":66}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":78},"end":{"line":1,"column":79}}}]"####,
        ),
        (
            r####"scope"####,
            r####"simple_identifier"####,
            r####"class C {  bool M(bool IsReady) {  if (true & IsReady) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":44},"end":{"line":1,"column":45}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":57},"end":{"line":1,"column":58}}}]"####,
        ),
        (
            r####"scope"####,
            r####"const_local"####,
            r####"class C {  bool M() { const int n = 2; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":48},"end":{"line":1,"column":49}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":61},"end":{"line":1,"column":62}}}]"####,
        ),
        (
            r####"scope"####,
            r####"const_bool"####,
            r####"class C {  bool M() { const bool flag = true; if (true & !flag) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":68},"end":{"line":1,"column":69}}}]"####,
        ),
        (
            r####"scope"####,
            r####"var_local"####,
            r####"class C {  bool M() { var n = 2; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":42},"end":{"line":1,"column":43}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"####,
        ),
        (
            r####"scope"####,
            r####"other_type"####,
            r####"class C {  bool M(long n) {  if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":38},"end":{"line":1,"column":39}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"####,
        ),
        (
            r####"scope"####,
            r####"field"####,
            r####"class C { int n; bool M() {  if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":38},"end":{"line":1,"column":39}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"####,
        ),
        (
            r####"scope"####,
            r####"member"####,
            r####"class C { int n; bool M() {  if (true & this.n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":38},"end":{"line":1,"column":39}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"####,
        ),
        (
            r####"scope"####,
            r####"unresolved"####,
            r####"class C {  bool M() {  if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":32},"end":{"line":1,"column":33}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":45},"end":{"line":1,"column":46}}}]"####,
        ),
        (
            r####"scope"####,
            r####"duplicate"####,
            r####"class C {  bool M(int n) { int n = 2; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":47},"end":{"line":1,"column":48}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":60},"end":{"line":1,"column":61}}}]"####,
        ),
        (
            r####"scope"####,
            r####"sibling"####,
            r####"class C {  bool M() { { int n = 2; } if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":46},"end":{"line":1,"column":47}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":59},"end":{"line":1,"column":60}}}]"####,
        ),
        (
            r####"scope"####,
            r####"sibling_conflict"####,
            r####"class C {  bool M(int n) { { int n = 2; } if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":64},"end":{"line":1,"column":65}}}]"####,
        ),
        (
            r####"scope"####,
            r####"future"####,
            r####"class C { bool M() { if (true & n < 4) return true; int n = 2; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":30},"end":{"line":1,"column":31}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":43},"end":{"line":1,"column":44}}}]"####,
        ),
        (
            r####"scope"####,
            r####"future_conflict"####,
            r####"class C { bool M(int n) { if (true & n < 4) return true; const int n = 2; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":35},"end":{"line":1,"column":36}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":48},"end":{"line":1,"column":49}}}]"####,
        ),
        (
            r####"runtime"####,
            r####"nested_block"####,
            r####"class C { bool M() { int n = 2; { if (true & n < 4) return true; } return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":43},"end":{"line":1,"column":44}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":56},"end":{"line":1,"column":57}}}]"####,
        ),
        (
            r####"scope"####,
            r####"lambda_owned"####,
            r####"class C {  bool M(int n) { System.Func<int> f = () => 2; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":66},"end":{"line":1,"column":67}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":79},"end":{"line":1,"column":80}}}]"####,
        ),
        (
            r####"scope"####,
            r####"anonymous_owned"####,
            r####"class C {  bool M(int n) { System.Func<int> f = delegate { return 2; }; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":81},"end":{"line":1,"column":82}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":94},"end":{"line":1,"column":95}}}]"####,
        ),
        (
            r####"scope"####,
            r####"local_function_owned"####,
            r####"class C {  bool M(int n) { int F() { return 2; } if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":58},"end":{"line":1,"column":59}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":71},"end":{"line":1,"column":72}}}]"####,
        ),
        (
            r####"scope"####,
            r####"for"####,
            r####"class C {  bool M(int n) { for (int i = 0; i < 1; i++) {} if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":67},"end":{"line":1,"column":68}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"####,
        ),
        (
            r####"scope"####,
            r####"foreach"####,
            r####"class C {  bool M(int n) { foreach (int i in new int[0]) {} if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":69},"end":{"line":1,"column":70}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":82},"end":{"line":1,"column":83}}}]"####,
        ),
        (
            r####"scope"####,
            r####"catch"####,
            r####"class C {  bool M(int n) { try {} catch (System.Exception e) {} if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":73},"end":{"line":1,"column":74}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":86},"end":{"line":1,"column":87}}}]"####,
        ),
        (
            r####"scope"####,
            r####"switch"####,
            r####"class C {  bool M(int n) { switch (n) { case 0: break; } if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":66},"end":{"line":1,"column":67}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":79},"end":{"line":1,"column":80}}}]"####,
        ),
        (
            r####"scope"####,
            r####"switch_expression"####,
            r####"class C {  bool M(int n) { int value = n switch { _ => 0 }; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":69},"end":{"line":1,"column":70}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":82},"end":{"line":1,"column":83}}}]"####,
        ),
        (
            r####"scope"####,
            r####"using"####,
            r####"class C {  bool M(int n) { using (var stream = new System.IO.MemoryStream()) {} if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":89},"end":{"line":1,"column":90}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":102},"end":{"line":1,"column":103}}}]"####,
        ),
        (
            r####"scope"####,
            r####"using_declaration"####,
            r####"class C {  bool M(int n) { using var stream = new System.IO.MemoryStream(); if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":85},"end":{"line":1,"column":86}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":98},"end":{"line":1,"column":99}}}]"####,
        ),
        (
            r####"scope"####,
            r####"fixed"####,
            r####"class C {  bool M(int n) { unsafe { fixed (int* p = new int[1]) {} } if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":78},"end":{"line":1,"column":79}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":91},"end":{"line":1,"column":92}}}]"####,
        ),
        (
            r####"scope"####,
            r####"pattern"####,
            r####"class C {  bool M(int n) { bool found = new object() is int value; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":76},"end":{"line":1,"column":77}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":89},"end":{"line":1,"column":90}}}]"####,
        ),
        (
            r####"scope"####,
            r####"declaration"####,
            r####"class C {  bool M(int n) { int.TryParse("2", out int value); if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":70},"end":{"line":1,"column":71}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":83},"end":{"line":1,"column":84}}}]"####,
        ),
        (
            r####"scope"####,
            r####"query"####,
            r####"class C {  bool M(int n) { var values = from value in new int[0] select value; if (true & n < 4) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":88},"end":{"line":1,"column":89}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":101},"end":{"line":1,"column":102}}}]"####,
        ),
        (
            r####"scope"####,
            r####"lambda_nearest"####,
            r####"class C { void M(int n) { System.Func<bool> f = () => { if (true & n < 4) return true; return false; }; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":65},"end":{"line":1,"column":66}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":78},"end":{"line":1,"column":79}}}]"####,
        ),
        (
            r####"scope"####,
            r####"local_function_nearest"####,
            r####"class C { void M(int n) { bool F() { if (true & n < 4) return true; return false; } } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":46},"end":{"line":1,"column":47}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":59},"end":{"line":1,"column":60}}}]"####,
        ),
        (
            r####"scope"####,
            r####"accessor_nearest"####,
            r####"class C { int n; bool P { get { if (true & n < 4) return true; return false; } } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_parameter_shadow"####,
            r####"class C { bool ReadFlag() { return true; } bool M(System.Func<bool> ReadFlag) {  if (true & !ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":90},"end":{"line":1,"column":91}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":103},"end":{"line":1,"column":104}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_local_shadow"####,
            r####"class C { bool ReadFlag() { return true; } bool M() { System.Func<bool> ReadFlag = null; if (true & !ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":98},"end":{"line":1,"column":99}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":111},"end":{"line":1,"column":112}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_future_shadow"####,
            r####"class C { bool ReadFlag() { return true; } bool M() { if (true & !ReadFlag()) return true; System.Func<bool> ReadFlag = null; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":63},"end":{"line":1,"column":64}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":76},"end":{"line":1,"column":77}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_overload"####,
            r####"class C { bool ReadFlag() { return true; } bool ReadFlag(int n) { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":102},"end":{"line":1,"column":103}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":115},"end":{"line":1,"column":116}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_duplicate"####,
            r####"class C { bool ReadFlag() { return true; } bool ReadFlag() { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":97},"end":{"line":1,"column":98}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":110},"end":{"line":1,"column":111}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_generic"####,
            r####"class C { bool ReadFlag<T>() { return true; } bool M() {  if (true & !ReadFlag<int>()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":67},"end":{"line":1,"column":68}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_member"####,
            r####"class C { bool ReadFlag() { return true; } bool M() {  if (true & !this.ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":64},"end":{"line":1,"column":65}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":77},"end":{"line":1,"column":78}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_argument"####,
            r####"class C { bool ReadFlag(int n) { return true; } bool M() {  if (true & !ReadFlag(1)) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":69},"end":{"line":1,"column":70}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":82},"end":{"line":1,"column":83}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_missing"####,
            r####"class C {  bool M() {  if (true & !ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":32},"end":{"line":1,"column":33}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":45},"end":{"line":1,"column":46}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_wrong_type"####,
            r####"class C { int ReadFlag() { return 1; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":60},"end":{"line":1,"column":61}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":73},"end":{"line":1,"column":74}}}]"####,
        ),
        (
            r####"call"####,
            r####"call_unsupported_owner"####,
            r####"class C { bool ReadFlag() { return true; } bool M() { System.Func<int> f = () => 2; if (true & !ReadFlag()) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":106},"end":{"line":1,"column":107}}}]"####,
        ),
        (
            r####"depth"####,
            r####"depth_limit"####,
            r####"class C {  bool M(bool flag) {  if (true & !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!flag) return true; return false; } }
"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"####,
            r####"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"####,
        ),
        (
            r####"depth"####,
            r####"parenthesized_detector"####,
            r####"class C {  bool M(int n) {  if (true & (n < 4)) return true; return false; } }
"####,
            r####"[]"####,
            r####"[]"####,
        ),
        (
            r####"depth"####,
            r####"logical_clean"####,
            r####"class C { bool M(bool flag) { if (true && !flag) return true; return false; } }
"####,
            r####"[]"####,
            r####"[]"####,
        ),
    ];

    fn controls(category: &str, selected_name: Option<&str>) {
        let mut failures = Vec::new();
        for &(kind, name, source, lf, unicode) in CONTROLS {
            if kind != category || selected_name.is_some_and(|wanted| wanted != name) {
                continue;
            }
            for (crlf, expected) in [(false, lf), (true, unicode)] {
                let text = if crlf {
                    source
                        .replace("if (", "/* 😀 café */ if (")
                        .replace('\n', "\r\n")
                } else {
                    source.to_owned()
                };
                let report = analyze_default(&text);
                let actual = serde_json::to_value(with_key(&report, "csharpsquid:S2178")).unwrap();
                let wanted: serde_json::Value = serde_json::from_str(expected).unwrap();
                if actual != wanted {
                    failures.push(format!(
                        "{name}, CRLF={crlf}: expected {wanted}, actual {actual}"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "S2178 full-object controls: {failures:#?}"
        );
    }

    #[test]
    fn s2178_runtime_witness_messages_and_operator_ranges() {
        controls("runtime", None);
    }

    #[test]
    fn s2178_humanizer_fourth_declarator_runtime_message() {
        controls("runtime", Some("humanizer_fourth_declarator"));
    }

    #[test]
    fn s2178_constant_and_unsupported_expression_messages_stay_short() {
        controls("constant", None);
    }

    #[test]
    fn s2178_scope_and_nearest_callable_messages_stay_short() {
        controls("scope", None);
    }

    #[test]
    fn s2178_ambiguous_or_unsupported_call_messages_stay_short() {
        controls("call", None);
    }

    #[test]
    fn s2178_depth_and_original_detector_boundaries() {
        controls("depth", None);
    }
}
