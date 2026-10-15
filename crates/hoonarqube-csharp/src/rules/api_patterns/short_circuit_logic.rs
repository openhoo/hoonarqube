use crate::CsLanguage;
use crate::cst::{
    ancestors_of, canonical_identifier, collect_kinds, integer_literal_natural_type,
    is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::dataflow::unary_operator;
use crate::rules::expressions::{binary_operands, enclosing_callable, enclosing_type, operator_of};
use crate::rules::naming::type_members;
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
        if looks_boolean_operand(left, source) && looks_boolean_operand(right, source) {
            let mut cursor = expression.walk();
            let operator = expression
                .children(&mut cursor)
                .find(|child| matches!(child.kind(), "&" | "|"))
                .unwrap_or(expression);
            let replacement = if operator.kind() == "&" { "&&" } else { "||" };
            let advice = operand_advice(right, source);
            issues.push(issue(
                language,
                "S2178",
                format!(
                    "Correct this '{}' to '{replacement}'{advice}.",
                    operator.kind()
                ),
                range_of(operator, source),
            ));
        }
    }
    issues
}

/// Preserve the original bare shapes; only checked parentheses add admission.
fn looks_boolean_operand(expression: Node<'_>, source: &str) -> bool {
    if expression.kind() == "parenthesized_expression" {
        parenthesized_terminal(expression)
            .is_some_and(|terminal| looks_boolean_expression(terminal, source))
    } else {
        looks_boolean_expression(expression, source)
    }
}

/// A terminal must fit in the same 64 visits used by operand facts. Comments
/// are extra named children and cannot be silently discarded while peeling.
fn parenthesized_terminal(mut expression: Node<'_>) -> Option<Node<'_>> {
    for _ in 0..64 {
        if expression.has_error()
            || is_error_tainted(expression)
            || enclosing_callable(expression).is_some_and(|owner| owner.has_error())
        {
            return None;
        }
        if expression.kind() != "parenthesized_expression" {
            return Some(expression);
        }
        let child = sole_child(expression)?;
        if child.is_extra() || child.is_missing() {
            return None;
        }
        expression = child;
    }
    None
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Primitive {
    Int,
    Bool,
}

/// Unknown is None: unsupported constant syntax must never imply runtime.
#[derive(Clone, Copy)]
struct OperandFact {
    primitive: Primitive,
    runtime: bool,
}

fn operand_advice(expression: Node<'_>, source: &str) -> &'static str {
    let identifier = expression.kind() == "identifier"
        || (expression.kind() == "parenthesized_expression"
            && parenthesized_terminal(expression)
                .is_some_and(|terminal| terminal.kind() == "identifier"));
    if !identifier
        && operand_fact(expression, source, 0)
            .is_some_and(|fact| fact.primitive == Primitive::Bool && fact.runtime)
    {
        " and extract the right operand to a variable if it should always be evaluated"
    } else {
        ""
    }
}

fn operand_fact(expression: Node<'_>, source: &str, depth: usize) -> Option<OperandFact> {
    if depth >= 64 || expression.has_error() || is_error_tainted(expression) {
        return None;
    }
    match expression.kind() {
        "boolean_literal" if matches!(node_text(expression, source), "true" | "false") => {
            Some(OperandFact {
                primitive: Primitive::Bool,
                runtime: false,
            })
        }
        "integer_literal"
            if integer_literal_natural_type(node_text(expression, source)) == Some("int") =>
        {
            Some(OperandFact {
                primitive: Primitive::Int,
                runtime: false,
            })
        }
        "identifier" => runtime_identifier(expression, source),
        "invocation_expression" => runtime_call(expression, source),
        "parenthesized_expression" => operand_fact(sole_child(expression)?, source, depth + 1),
        "prefix_unary_expression" if unary_operator(expression) == Some("!") => {
            let fact = operand_fact(sole_child(expression)?, source, depth + 1)?;
            (fact.primitive == Primitive::Bool).then_some(fact)
        }
        "binary_expression" if matches!(operator_of(expression), Some("&&" | "||")) => {
            logical_fact(expression, source, depth + 1)
        }
        "binary_expression" => comparison_fact(expression, source, depth + 1),
        _ => None,
    }
}

fn sole_child(expression: Node<'_>) -> Option<Node<'_>> {
    (expression.named_child_count() == 1)
        .then(|| expression.named_child(0))
        .flatten()
}

/// Only two direct runtime Bool identifiers, or two valid Bool literals,
/// have qualified logical facts. Mixed and compound children remain Unknown.
fn logical_fact(expression: Node<'_>, source: &str, depth: usize) -> Option<OperandFact> {
    let (left, right) = binary_operands(expression)?;
    let runtime = match (left.kind(), right.kind()) {
        ("identifier", "identifier") => true,
        ("boolean_literal", "boolean_literal") => false,
        _ => return None,
    };
    let left = operand_fact(left, source, depth)?;
    let right = operand_fact(right, source, depth)?;
    (left.primitive == Primitive::Bool
        && right.primitive == Primitive::Bool
        && left.runtime == runtime
        && right.runtime == runtime)
        .then_some(OperandFact {
            primitive: Primitive::Bool,
            runtime,
        })
}

fn comparison_fact(expression: Node<'_>, source: &str, depth: usize) -> Option<OperandFact> {
    let operator = operator_of(expression)?;
    if !matches!(operator, "==" | "!=" | "<" | "<=" | ">" | ">=") {
        return None;
    }
    let (left, right) = binary_operands(expression)?;
    let left = operand_fact(left, source, depth)?;
    let right = operand_fact(right, source, depth)?;
    if left.primitive != right.primitive
        || (!matches!(operator, "==" | "!=") && left.primitive != Primitive::Int)
    {
        return None;
    }
    Some(OperandFact {
        primitive: Primitive::Bool,
        runtime: left.runtime || right.runtime,
    })
}

fn primitive_type(node: Node<'_>, source: &str) -> Option<Primitive> {
    if node.kind() != "predefined_type" {
        return None;
    }
    match node_text(node, source) {
        "int" => Some(Primitive::Int),
        "bool" => Some(Primitive::Bool),
        _ => None,
    }
}

/// Refuse binding constructs that need a broader C# scope resolver. The nearest
/// callable is authoritative; never reach through a closure to its method.
fn witness_owner(expression: Node<'_>) -> Option<Node<'_>> {
    let owner = enclosing_callable(expression)?;
    if owner.kind() != "method_declaration" || owner.has_error() || is_error_tainted(owner) {
        return None;
    }
    owner
        .child_by_field_name("body")
        .filter(|body| body.kind() == "block")?;
    let parameters = owner
        .child_by_field_name("parameters")
        .filter(|list| list.kind() == "parameter_list")?;
    if !ordinary_parameter_list(parameters) {
        return None;
    }
    let unsupported = collect_kinds(
        owner,
        &[
            "lambda_expression",
            "anonymous_method_expression",
            "local_function_statement",
            "for_statement",
            "foreach_statement",
            "catch_clause",
            "catch_declaration",
            "switch_statement",
            "switch_expression",
            "using_statement",
            "fixed_statement",
            "is_pattern_expression",
            "declaration_expression",
            "query_expression",
            "tuple_pattern",
        ],
    );
    if !unsupported.is_empty()
        || collect_kinds(owner, &["local_declaration_statement"])
            .into_iter()
            .any(has_using_or_await)
    {
        return None;
    }
    Some(owner)
}

// parameters_of deliberately omits flattened params syntax. Refuse the whole
// owner before inventory so an omitted shadow never exposes a fallback.
fn ordinary_parameter_list(parameters: Node<'_>) -> bool {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .all(|child| child.kind() == "parameter")
}

fn has_using_or_await(statement: Node<'_>) -> bool {
    let mut cursor = statement.walk();
    statement
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "using" | "await"))
}

fn declaration_name<'a>(declaration: Node<'_>, source: &'a str) -> Option<&'a str> {
    let name = declaration.child_by_field_name("name")?;
    (name.kind() == "identifier").then(|| canonical_identifier(node_text(name, source)))
}

/// Count every same-name declaration, even a late/const/sibling local. A
/// rejected declaration must not expose a different parameter as a fallback.
fn matching_declarations<'t>(owner: Node<'t>, name: &str, source: &str) -> Vec<Node<'t>> {
    parameters_of(owner)
        .into_iter()
        .chain(
            collect_kinds(owner, &["variable_declarator"])
                .into_iter()
                .filter(|node| {
                    enclosing_callable(*node).is_some_and(|callable| callable.id() == owner.id())
                }),
        )
        .filter(|declaration| declaration_name(*declaration, source) == Some(name))
        .collect()
}

fn runtime_identifier(expression: Node<'_>, source: &str) -> Option<OperandFact> {
    let owner = witness_owner(expression)?;
    let name = canonical_identifier(node_text(expression, source));
    let declarations = matching_declarations(owner, name, source);
    let [declaration] = declarations.as_slice() else {
        return None;
    };
    let primitive = if declaration.kind() == "parameter" {
        primitive_type(declaration.child_by_field_name("type")?, source)?
    } else {
        local_primitive(*declaration, expression, source)?
    };
    Some(OperandFact {
        primitive,
        runtime: true,
    })
}

fn local_primitive(declarator: Node<'_>, expression: Node<'_>, source: &str) -> Option<Primitive> {
    let declaration = declarator
        .parent()
        .filter(|parent| parent.kind() == "variable_declaration")?;
    let statement = declaration
        .parent()
        .filter(|parent| parent.kind() == "local_declaration_statement")?;
    let block = statement
        .parent()
        .filter(|parent| parent.kind() == "block")?;
    if statement.end_byte() > expression.start_byte()
        || modifiers_of(statement, source).contains(&"const")
        || has_using_or_await(statement)
        || !ancestors_of(expression).any(|ancestor| ancestor.id() == block.id())
    {
        return None;
    }
    primitive_type(declaration.child_by_field_name("type")?, source)
}

fn runtime_call(expression: Node<'_>, source: &str) -> Option<OperandFact> {
    let function = expression
        .child_by_field_name("function")
        .filter(|node| node.kind() == "identifier")?;
    let arguments = expression
        .child_by_field_name("arguments")
        .filter(|node| node.kind() == "argument_list")?;
    if arguments.named_child_count() != 0 {
        return None;
    }
    let owner = witness_owner(expression)?;
    let name = canonical_identifier(node_text(function, source));
    if !matching_declarations(owner, name, source).is_empty() {
        return None;
    }
    let methods: Vec<_> = type_members(enclosing_type(expression)?)
        .into_iter()
        .filter(|member| {
            member.kind() == "method_declaration" && declaration_name(*member, source) == Some(name)
        })
        .collect();
    let [method] = methods.as_slice() else {
        return None;
    };
    zero_argument_bool_method(*method, source).then_some(OperandFact {
        primitive: Primitive::Bool,
        runtime: true,
    })
}

fn zero_argument_bool_method(method: Node<'_>, source: &str) -> bool {
    !method.has_error()
        && !is_error_tainted(method)
        && method.child_by_field_name("type_parameters").is_none()
        && method
            .child_by_field_name("parameters")
            .is_some_and(|list| list.kind() == "parameter_list" && list.named_child_count() == 0)
        && method
            .child_by_field_name("returns")
            .and_then(|node| primitive_type(node, source))
            == Some(Primitive::Bool)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    // These full objects are frozen from unchanged CLI controls, with only
    // independently selected runtime message replacements. Unknown stays short.
    const CONTROLS: &[(&str, &str, &str, &str, &str)] = &[
        (
            "runtime",
            "int_==_&",
            r"class C {  bool M(int n) {  if (true & n == 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_==_|",
            r"class C {  bool M(int n) {  if (true | n == 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_!=_&",
            r"class C {  bool M(int n) {  if (true & n != 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_!=_|",
            r"class C {  bool M(int n) {  if (true | n != 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_<_&",
            r"class C {  bool M(int n) {  if (true & n < 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_<_|",
            r"class C {  bool M(int n) {  if (true | n < 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_<=_&",
            r"class C {  bool M(int n) {  if (true & n <= 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_<=_|",
            r"class C {  bool M(int n) {  if (true | n <= 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_>_&",
            r"class C {  bool M(int n) {  if (true & n > 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_>_|",
            r"class C {  bool M(int n) {  if (true | n > 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_>=_&",
            r"class C {  bool M(int n) {  if (true & n >= 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "int_>=_|",
            r"class C {  bool M(int n) {  if (true | n >= 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "constant",
            "long",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1L < 2L) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "uint",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1U < 2U) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "ulong",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1UL < 2UL) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "float",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1F < 2F) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "double",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1.0 < 2.0) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "decimal",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1M < 2M) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "char",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 'a' == 'b') return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "string",
            r#"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & "a" == "b") return true; return false; } }
"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "arithmetic",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1 + 2 < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "runtime_arithmetic",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & n + 1 < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "local_const",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & limit < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "field_const",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & Limit < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "enum",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & E.One == E.Two) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "maxvalue",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & int.MaxValue > 0) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "const_negation",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & !flag) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "nameof",
            r#"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & nameof(n) == "n") return true; return false; } }
"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "cast",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & (int)n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "checked",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & checked(n + 1) < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "unchecked",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & unchecked(n + 1) < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "default",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & default(int) == 0) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "bool_literal",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & !true) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "int_literal",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1 < 2) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "bool_equality",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & true != false) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "constant",
            "null_equality",
            r"class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & null == null) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":121},"end":{"line":1,"column":122}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":134},"end":{"line":1,"column":135}}}]"#,
        ),
        (
            "runtime",
            "humanizer_fourth_declarator",
            r"class C {  bool M() { int seconds = 0, minutes = 1, hours = 2, days = 30; days += 1; if (true & days <= 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":94},"end":{"line":1,"column":95}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":107},"end":{"line":1,"column":108}}}]"#,
        ),
        (
            "runtime",
            "literal_local",
            r"class C {  bool M() { int n = 2; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":42},"end":{"line":1,"column":43}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"#,
        ),
        (
            "runtime",
            "call_initializer",
            r"class C { int Read() { return 2; } bool M() { int n = Read(); n++; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":76},"end":{"line":1,"column":77}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":89},"end":{"line":1,"column":90}}}]"#,
        ),
        (
            "runtime",
            "member_initializer",
            r"class C { int Value; bool M() { int n = Value; n = 3; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":63},"end":{"line":1,"column":64}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":76},"end":{"line":1,"column":77}}}]"#,
        ),
        (
            "runtime",
            "bool_local",
            r"class C {  bool M() { bool flag = true; if (true & !flag) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":49},"end":{"line":1,"column":50}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":62},"end":{"line":1,"column":63}}}]"#,
        ),
        (
            "runtime",
            "optional_parameter",
            r"class C {  bool M(int n = 2) {  if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"#,
        ),
        (
            "runtime",
            "escaped_parameter",
            r"class C {  bool M(int @value) {  if (true & @value < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":42},"end":{"line":1,"column":43}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"#,
        ),
        (
            "runtime",
            "escaped_local",
            r"class C {  bool M() { int @value = 2; if (true & @value < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":47},"end":{"line":1,"column":48}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":60},"end":{"line":1,"column":61}}}]"#,
        ),
        (
            "runtime",
            "bool_parameter_equality",
            r"class C {  bool M(bool flag) {  if (true & flag == false) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"#,
        ),
        (
            "runtime",
            "comparison_negation",
            r"class C {  bool M(int n) {  if (true & !(n < 4)) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"#,
        ),
        (
            "runtime",
            "bool_parameter_negation",
            r"class C {  bool M(bool flag) {  if (true & !flag) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"#,
        ),
        (
            "runtime",
            "declared_call",
            r"class C { bool ReadFlag() { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":64},"end":{"line":1,"column":65}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":77},"end":{"line":1,"column":78}}}]"#,
        ),
        (
            "runtime",
            "escaped_call",
            r"class C { bool @ReadFlag() { return true; } bool M() {  if (true & !@ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":65},"end":{"line":1,"column":66}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":78},"end":{"line":1,"column":79}}}]"#,
        ),
        (
            "scope",
            "simple_identifier",
            r"class C {  bool M(bool IsReady) {  if (true & IsReady) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":44},"end":{"line":1,"column":45}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":57},"end":{"line":1,"column":58}}}]"#,
        ),
        (
            "scope",
            "const_local",
            r"class C {  bool M() { const int n = 2; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":48},"end":{"line":1,"column":49}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":61},"end":{"line":1,"column":62}}}]"#,
        ),
        (
            "scope",
            "const_bool",
            r"class C {  bool M() { const bool flag = true; if (true & !flag) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":68},"end":{"line":1,"column":69}}}]"#,
        ),
        (
            "scope",
            "var_local",
            r"class C {  bool M() { var n = 2; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":42},"end":{"line":1,"column":43}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"#,
        ),
        (
            "scope",
            "other_type",
            r"class C {  bool M(long n) {  if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":38},"end":{"line":1,"column":39}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"#,
        ),
        (
            "scope",
            "field",
            r"class C { int n; bool M() {  if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":38},"end":{"line":1,"column":39}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"#,
        ),
        (
            "scope",
            "member",
            r"class C { int n; bool M() {  if (true & this.n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":38},"end":{"line":1,"column":39}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"#,
        ),
        (
            "scope",
            "unresolved",
            r"class C {  bool M() {  if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":32},"end":{"line":1,"column":33}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":45},"end":{"line":1,"column":46}}}]"#,
        ),
        (
            "scope",
            "duplicate",
            r"class C {  bool M(int n) { int n = 2; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":47},"end":{"line":1,"column":48}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":60},"end":{"line":1,"column":61}}}]"#,
        ),
        (
            "scope",
            "sibling",
            r"class C {  bool M() { { int n = 2; } if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":46},"end":{"line":1,"column":47}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":59},"end":{"line":1,"column":60}}}]"#,
        ),
        (
            "scope",
            "sibling_conflict",
            r"class C {  bool M(int n) { { int n = 2; } if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":64},"end":{"line":1,"column":65}}}]"#,
        ),
        (
            "scope",
            "future",
            r"class C { bool M() { if (true & n < 4) return true; int n = 2; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":30},"end":{"line":1,"column":31}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":43},"end":{"line":1,"column":44}}}]"#,
        ),
        (
            "scope",
            "future_conflict",
            r"class C { bool M(int n) { if (true & n < 4) return true; const int n = 2; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":35},"end":{"line":1,"column":36}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":48},"end":{"line":1,"column":49}}}]"#,
        ),
        (
            "runtime",
            "nested_block",
            r"class C { bool M() { int n = 2; { if (true & n < 4) return true; } return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":43},"end":{"line":1,"column":44}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":56},"end":{"line":1,"column":57}}}]"#,
        ),
        (
            "scope",
            "lambda_owned",
            r"class C {  bool M(int n) { System.Func<int> f = () => 2; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":66},"end":{"line":1,"column":67}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":79},"end":{"line":1,"column":80}}}]"#,
        ),
        (
            "scope",
            "anonymous_owned",
            r"class C {  bool M(int n) { System.Func<int> f = delegate { return 2; }; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":81},"end":{"line":1,"column":82}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":94},"end":{"line":1,"column":95}}}]"#,
        ),
        (
            "scope",
            "local_function_owned",
            r"class C {  bool M(int n) { int F() { return 2; } if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":58},"end":{"line":1,"column":59}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":71},"end":{"line":1,"column":72}}}]"#,
        ),
        (
            "scope",
            "for",
            r"class C {  bool M(int n) { for (int i = 0; i < 1; i++) {} if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":67},"end":{"line":1,"column":68}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"#,
        ),
        (
            "scope",
            "foreach",
            r"class C {  bool M(int n) { foreach (int i in new int[0]) {} if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":69},"end":{"line":1,"column":70}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":82},"end":{"line":1,"column":83}}}]"#,
        ),
        (
            "scope",
            "catch",
            r"class C {  bool M(int n) { try {} catch (System.Exception e) {} if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":73},"end":{"line":1,"column":74}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":86},"end":{"line":1,"column":87}}}]"#,
        ),
        (
            "scope",
            "switch",
            r"class C {  bool M(int n) { switch (n) { case 0: break; } if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":66},"end":{"line":1,"column":67}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":79},"end":{"line":1,"column":80}}}]"#,
        ),
        (
            "scope",
            "switch_expression",
            r"class C {  bool M(int n) { int value = n switch { _ => 0 }; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":69},"end":{"line":1,"column":70}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":82},"end":{"line":1,"column":83}}}]"#,
        ),
        (
            "scope",
            "using",
            r"class C {  bool M(int n) { using (var stream = new System.IO.MemoryStream()) {} if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":89},"end":{"line":1,"column":90}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":102},"end":{"line":1,"column":103}}}]"#,
        ),
        (
            "scope",
            "using_declaration",
            r"class C {  bool M(int n) { using var stream = new System.IO.MemoryStream(); if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":85},"end":{"line":1,"column":86}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":98},"end":{"line":1,"column":99}}}]"#,
        ),
        (
            "scope",
            "fixed",
            r"class C {  bool M(int n) { unsafe { fixed (int* p = new int[1]) {} } if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":78},"end":{"line":1,"column":79}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":91},"end":{"line":1,"column":92}}}]"#,
        ),
        (
            "scope",
            "pattern",
            r"class C {  bool M(int n) { bool found = new object() is int value; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":76},"end":{"line":1,"column":77}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":89},"end":{"line":1,"column":90}}}]"#,
        ),
        (
            "scope",
            "declaration",
            r#"class C {  bool M(int n) { int.TryParse("2", out int value); if (true & n < 4) return true; return false; } }
"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":70},"end":{"line":1,"column":71}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":83},"end":{"line":1,"column":84}}}]"#,
        ),
        (
            "scope",
            "query",
            r"class C {  bool M(int n) { var values = from value in new int[0] select value; if (true & n < 4) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":88},"end":{"line":1,"column":89}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":101},"end":{"line":1,"column":102}}}]"#,
        ),
        (
            "scope",
            "lambda_nearest",
            r"class C { void M(int n) { System.Func<bool> f = () => { if (true & n < 4) return true; return false; }; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":65},"end":{"line":1,"column":66}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":78},"end":{"line":1,"column":79}}}]"#,
        ),
        (
            "scope",
            "local_function_nearest",
            r"class C { void M(int n) { bool F() { if (true & n < 4) return true; return false; } } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":46},"end":{"line":1,"column":47}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":59},"end":{"line":1,"column":60}}}]"#,
        ),
        (
            "scope",
            "accessor_nearest",
            r"class C { int n; bool P { get { if (true & n < 4) return true; return false; } } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"#,
        ),
        (
            "call",
            "call_parameter_shadow",
            r"class C { bool ReadFlag() { return true; } bool M(System.Func<bool> ReadFlag) {  if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":90},"end":{"line":1,"column":91}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":103},"end":{"line":1,"column":104}}}]"#,
        ),
        (
            "call",
            "call_local_shadow",
            r"class C { bool ReadFlag() { return true; } bool M() { System.Func<bool> ReadFlag = null; if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":98},"end":{"line":1,"column":99}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":111},"end":{"line":1,"column":112}}}]"#,
        ),
        (
            "call",
            "call_future_shadow",
            r"class C { bool ReadFlag() { return true; } bool M() { if (true & !ReadFlag()) return true; System.Func<bool> ReadFlag = null; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":63},"end":{"line":1,"column":64}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":76},"end":{"line":1,"column":77}}}]"#,
        ),
        (
            "call",
            "call_overload",
            r"class C { bool ReadFlag() { return true; } bool ReadFlag(int n) { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":102},"end":{"line":1,"column":103}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":115},"end":{"line":1,"column":116}}}]"#,
        ),
        (
            "call",
            "call_duplicate",
            r"class C { bool ReadFlag() { return true; } bool ReadFlag() { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":97},"end":{"line":1,"column":98}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":110},"end":{"line":1,"column":111}}}]"#,
        ),
        (
            "call",
            "call_generic",
            r"class C { bool ReadFlag<T>() { return true; } bool M() {  if (true & !ReadFlag<int>()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":67},"end":{"line":1,"column":68}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"#,
        ),
        (
            "call",
            "call_member",
            r"class C { bool ReadFlag() { return true; } bool M() {  if (true & !this.ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":64},"end":{"line":1,"column":65}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":77},"end":{"line":1,"column":78}}}]"#,
        ),
        (
            "call",
            "call_argument",
            r"class C { bool ReadFlag(int n) { return true; } bool M() {  if (true & !ReadFlag(1)) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":69},"end":{"line":1,"column":70}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":82},"end":{"line":1,"column":83}}}]"#,
        ),
        (
            "call",
            "call_missing",
            r"class C {  bool M() {  if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":32},"end":{"line":1,"column":33}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":45},"end":{"line":1,"column":46}}}]"#,
        ),
        (
            "call",
            "call_wrong_type",
            r"class C { int ReadFlag() { return 1; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":60},"end":{"line":1,"column":61}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":73},"end":{"line":1,"column":74}}}]"#,
        ),
        (
            "call",
            "call_unsupported_owner",
            r"class C { bool ReadFlag() { return true; } bool M() { System.Func<int> f = () => 2; if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":106},"end":{"line":1,"column":107}}}]"#,
        ),
        (
            "depth",
            "depth_limit",
            r"class C {  bool M(bool flag) {  if (true & !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!flag) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":41},"end":{"line":1,"column":42}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":54},"end":{"line":1,"column":55}}}]"#,
        ),
        (
            "depth",
            "parenthesized_detector",
            r"class C {  bool M(int n) {  if (true & (n < 4)) return true; return false; } }
",
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":37},"end":{"line":1,"column":38}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":50},"end":{"line":1,"column":51}}}]"###,
        ),
        (
            "depth",
            "logical_clean",
            r"class C { bool M(bool flag) { if (true && !flag) return true; return false; } }
",
            "[]",
            "[]",
        ),
        (
            "error",
            "error-child-call",
            r"class C { bool ReadFlag() { return true; } bool M() { if (true & !ReadFlag(,)) return true; return false; } }
",
            "[]",
            "[]",
        ),
        (
            "error",
            "error-child-comparison",
            r"class C { bool M(int n) { if (true & n <= (1 + )) return true; return false; } }
",
            "[]",
            "[]",
        ),
        (
            "error",
            "error-owner",
            r"class C { bool M(int n) { if (true & n <= 31) return true; int broken = ; return false; } }
",
            "[]",
            "[]",
        ),
        (
            "params",
            "params-callee-shadow",
            r"class C { bool ReadFlag() { return true; } bool M(params System.Func<bool>[] ReadFlag) { if (true & !ReadFlag()) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":98},"end":{"line":1,"column":99}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":98},"end":{"line":1,"column":99}}}]"#,
        ),
        (
            "params",
            "params-runtime-comparison",
            r"class C { bool M(int n, params int[] values) { if (true & n <= 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":56},"end":{"line":1,"column":57}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":56},"end":{"line":1,"column":57}}}]"#,
        ),
        (
            "params",
            "params-duplicate-fallback",
            r"class C { bool M(int n, params int[] n) { if (true & n <= 31) return true; return false; } }
",
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"#,
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"#,
        ),
    ];

    fn controls(category: &str, selected_name: Option<&str>) {
        let mut failures = Vec::new();
        for &(kind, name, source, lf, unicode) in CONTROLS {
            if kind != category || selected_name.is_some_and(|wanted| wanted != name) {
                continue;
            }
            for (crlf, expected) in [(false, lf), (true, unicode)] {
                let text = if crlf && !matches!(kind, "error" | "params") {
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
    #[test]
    fn s2178_error_children_and_owner_keep_unknown_short() {
        controls("error", None);
    }
    #[test]
    fn s2178_flattened_params_preserve_unknown_inventory() {
        controls("params", None);
    }
    // Native preservation controls; actual-reference qualification is limited to the typed CLI matrix.
    const PARENTHESIZED_CONTROLS: &[(&str, &str, &str, &str, &str)] = &[
        (
            r###"wrapper"###,
            r###"left_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if ((true) & n < 4) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":82},"end":{"line":1,"column":83}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":95},"end":{"line":1,"column":96}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"right_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (n < 4)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"both_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (((true)) & ((n < 4))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":84},"end":{"line":1,"column":85}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":97},"end":{"line":1,"column":98}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"identifier_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if ((IsReady) & ((HasItems))) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"wrapper"###,
            r###"literal_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (((true)) & ((false))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":84},"end":{"line":1,"column":85}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":97},"end":{"line":1,"column":98}}}]"###,
        ),
        (
            r###"logical"###,
            r###"logical_ids_&&_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"logical"###,
            r###"logical_literals_&&_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (true && false)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_false_&&_HasItems_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (false && HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_true_&&_HasItems_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (true && HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_HasItems_&&_false_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems && false)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_HasItems_&&_true_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems && true)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"logical"###,
            r###"logical_ids_||_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems || CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"logical"###,
            r###"logical_literals_||_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (true || false)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_false_||_HasItems_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (false || HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_true_||_HasItems_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (true || HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_HasItems_||_false_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems || false)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_HasItems_||_true_&"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems || true)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"left_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if ((true) | n < 4) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":82},"end":{"line":1,"column":83}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":95},"end":{"line":1,"column":96}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"right_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (n < 4)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"both_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (((true)) | ((n < 4))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":84},"end":{"line":1,"column":85}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":97},"end":{"line":1,"column":98}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"identifier_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if ((IsReady) | ((HasItems))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":85},"end":{"line":1,"column":86}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":98},"end":{"line":1,"column":99}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"literal_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (((true)) | ((false))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":84},"end":{"line":1,"column":85}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":97},"end":{"line":1,"column":98}}}]"###,
        ),
        (
            r###"logical"###,
            r###"logical_ids_&&_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"logical"###,
            r###"logical_literals_&&_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (true && false)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_false_&&_HasItems_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (false && HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_true_&&_HasItems_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (true && HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_HasItems_&&_false_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems && false)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_HasItems_&&_true_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems && true)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"logical"###,
            r###"logical_ids_||_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems || CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"logical"###,
            r###"logical_literals_||_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (true || false)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_false_||_HasItems_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (false || HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_true_||_HasItems_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (true || HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_HasItems_||_false_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems || false)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"mixed_HasItems_||_true_|"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems || true)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_child_call"###,
            r###"class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (ReadFlag() && HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":112},"end":{"line":1,"column":113}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":125},"end":{"line":1,"column":126}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_child_comparison"###,
            r###"class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (n < 4 && HasItems)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":112},"end":{"line":1,"column":113}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":125},"end":{"line":1,"column":126}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_child_unary"###,
            r###"class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (!HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":112},"end":{"line":1,"column":113}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":125},"end":{"line":1,"column":126}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_child_wrapped"###,
            r###"class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((HasItems) && CanFail)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_child_nested"###,
            r###"class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems && CanFail && IsReady)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":112},"end":{"line":1,"column":113}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":125},"end":{"line":1,"column":126}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_binding_params"###,
            r###"class C {  bool M(bool HasItems, bool CanFail, params int[] values) {  if (true & (HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_binding_duplicate"###,
            r###"class C {  bool M(bool HasItems, bool CanFail) { bool HasItems = true; if (true & (HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_binding_const"###,
            r###"class C {  bool M(bool CanFail) { const bool HasItems = true; if (true & (HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":71},"end":{"line":1,"column":72}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":84},"end":{"line":1,"column":85}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_binding_var"###,
            r###"class C {  bool M(bool CanFail) { var HasItems = true; if (true & (HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":64},"end":{"line":1,"column":65}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":77},"end":{"line":1,"column":78}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_binding_late"###,
            r###"class C { bool M(bool CanFail) { if (true & (HasItems && CanFail)) return true; bool HasItems = true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":42},"end":{"line":1,"column":43}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":55},"end":{"line":1,"column":56}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_binding_other_type"###,
            r###"class C {  bool M(int HasItems, bool CanFail) {  if (true & (HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":58},"end":{"line":1,"column":59}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":71},"end":{"line":1,"column":72}}}]"###,
        ),
        (
            r###"unknown"###,
            r###"logical_binding_owner"###,
            r###"class C {  bool M(bool HasItems, bool CanFail) { System.Func<bool> f = () => true; if (true & (HasItems && CanFail)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":92},"end":{"line":1,"column":93}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":105},"end":{"line":1,"column":106}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"direct_invocation"###,
            r###"class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (ReadFlag())) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"wrapper"###,
            r###"wrapped_negated_call"###,
            r###"class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (!ReadFlag())) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":112},"end":{"line":1,"column":113}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":125},"end":{"line":1,"column":126}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"ordinary_name"###,
            r###"class C {  bool M(bool flag) {  if (true & (flag)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"wrapper"###,
            r###"cast"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((bool)HasItems)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"wrapper"###,
            r###"arithmetic"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (n + 1)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"wrapper"###,
            r###"bitwise_child"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (n & 1)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"wrapper"###,
            r###"outside_assignment"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  bool value = true & (HasItems && CanFail); return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"wrapper"###,
            r###"outside_return"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  return true & (HasItems && CanFail); return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"context"###,
            r###"condition_while"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  while (true & (n < 4)) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":83},"end":{"line":1,"column":84}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":83},"end":{"line":1,"column":84}}}]"###,
        ),
        (
            r###"context"###,
            r###"condition_do"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  do { n++; } while (true & (n < 4)); return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":95},"end":{"line":1,"column":96}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":95},"end":{"line":1,"column":96}}}]"###,
        ),
        (
            r###"context"###,
            r###"condition_for"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  for (; true & (n < 4);) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":83},"end":{"line":1,"column":84}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":83},"end":{"line":1,"column":84}}}]"###,
        ),
        (
            r###"wrapper"###,
            r###"logical_only"###,
            r###"class C { bool M() { if ((true) && (false)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"context"###,
            r###"nearest_lambda"###,
            r###"class C { void M(bool HasItems, bool CanFail) { System.Func<bool> f = () => { if (true & (HasItems && CanFail)) return true; return false; }; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":87},"end":{"line":1,"column":88}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":100},"end":{"line":1,"column":101}}}]"###,
        ),
        (
            r###"context"###,
            r###"nearest_local_function"###,
            r###"class C { void M(bool HasItems, bool CanFail) { bool F() { if (true & (HasItems && CanFail)) return true; return false; } } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":68},"end":{"line":1,"column":69}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":81},"end":{"line":1,"column":82}}}]"###,
        ),
        (
            r###"context"###,
            r###"nearest_accessor"###,
            r###"class C { bool HasItems, CanFail; bool P { get { if (true & (HasItems && CanFail)) return true; return false; } } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":58},"end":{"line":1,"column":59}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":71},"end":{"line":1,"column":72}}}]"###,
        ),
        (
            r###"refusal"###,
            r###"comment_before"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (/* note */ HasItems)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"refusal"###,
            r###"comment_after"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems /* note */)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"refusal"###,
            r###"comment_inner"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((/* note */ HasItems))) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"depth"###,
            r###"literal_depth_62"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((false))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"depth"###,
            r###"comparison_depth_62"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((n < 4))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"depth"###,
            r###"literal_depth_63"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((false)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"depth"###,
            r###"comparison_depth_63"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((n < 4)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":80},"end":{"line":1,"column":81}}}]"###,
            r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":93},"end":{"line":1,"column":94}}}]"###,
        ),
        (
            r###"depth"###,
            r###"literal_depth_64"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((false))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"depth"###,
            r###"comparison_depth_64"###,
            r###"class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((n < 4))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"malformed"###,
            r###"extra"###,
            r###"class C { bool M(bool HasItems) { if (true & (HasItems false)) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"malformed"###,
            r###"missing"###,
            r###"class C { bool M() { if (true & ()) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"malformed"###,
            r###"child_error"###,
            r###"class C { bool M(int n) { if (true & (n < )) return true; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
        (
            r###"malformed"###,
            r###"owner_error"###,
            r###"class C { bool M(int n) { if (true & (n < 4)) return true; int broken = ; return false; } }
"###,
            r###"[]"###,
            r###"[]"###,
        ),
    ];

    fn parenthesized_controls(category: &str) {
        let mut failures = Vec::new();
        for &(kind, name, source, lf, unicode) in PARENTHESIZED_CONTROLS {
            if kind != category {
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
            "parenthesized S2178 full-object controls: {failures:#?}"
        );
    }

    #[test]
    fn s2178_parenthesized_context_full_objects() {
        parenthesized_controls("context");
    }

    #[test]
    fn s2178_parenthesized_depth_full_objects() {
        parenthesized_controls("depth");
    }

    #[test]
    fn s2178_parenthesized_logical_full_objects() {
        parenthesized_controls("logical");
    }

    #[test]
    fn s2178_parenthesized_malformed_full_objects() {
        parenthesized_controls("malformed");
    }

    #[test]
    fn s2178_parenthesized_refusal_full_objects() {
        parenthesized_controls("refusal");
    }

    #[test]
    fn s2178_parenthesized_unknown_full_objects() {
        parenthesized_controls("unknown");
    }

    #[test]
    fn s2178_parenthesized_wrapper_full_objects() {
        parenthesized_controls("wrapper");
    }
}
