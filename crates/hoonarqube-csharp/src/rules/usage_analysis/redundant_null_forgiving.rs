use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::resolved_identifier_type;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S8969 — the null-forgiving `!` operator is redundant on
/// operands the compiler already knows cannot be null.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for postfix in collect_kinds(root, &["postfix_unary_expression"]) {
        if is_error_tainted(postfix) || !is_null_forgiving(postfix, source) {
            continue;
        }
        let mut cursor = postfix.walk();
        let operand = postfix
            .children(&mut cursor)
            .find(tree_sitter::Node::is_named)
            .or_else(|| {
                let mut cursor = postfix.walk();
                postfix
                    .children(&mut cursor)
                    .find(|child| node_text(*child, source) == "this")
            });
        let Some(operand) = operand else {
            continue;
        };
        if operand_is_provably_non_null(operand, source) {
            issues.push(issue(
                language,
                "S8969",
                "Remove this null-forgiving operator; the compiler already knows this expression is not null here.",
                range_of(postfix, source),
            ));
        }
    }
    issues
}

/// Whether the postfix node is the null-forgiving `expr!` form: its last
/// unnamed child is `!` (distinguishing it from `++`/`--`).
fn is_null_forgiving(postfix: Node<'_>, source: &str) -> bool {
    let mut cursor = postfix.walk();
    postfix
        .children(&mut cursor)
        .filter(|child| !child.is_named())
        .last()
        .is_some_and(|operator| node_text(operator, source) == "!")
}

fn operand_is_provably_non_null(operand: Node<'_>, source: &str) -> bool {
    match operand.kind() {
        // `this` is never null; the grammar emits it unnamed, so the
        // caller also matches the bare `this` text on unnamed operands.
        // `new T()` never yields null either.
        "this"
        | "this_expression"
        | "object_creation_expression"
        | "implicit_object_creation_expression" => true,
        // Literals are never null.
        "string_literal"
        | "verbatim_string_literal"
        | "interpolated_string_expression"
        | "integer_literal"
        | "real_literal"
        | "character_literal"
        | "boolean_literal"
        | "null_literal" => false, // null_literal! is not redundant — it asserts non-null
        // A parenthesized operand inherits the inner expression's nullability.
        "parenthesized_expression" => operand
            .child_by_field_name("expression")
            .or_else(|| {
                let mut cursor = operand.walk();
                operand
                    .children(&mut cursor)
                    .find(tree_sitter::Node::is_named)
            })
            .is_some_and(|inner| operand_is_provably_non_null(inner, source)),
        // Identifiers and `this.member` accesses are non-null when their
        // resolved declaration type lacks a trailing `?`. `var` is treated
        // as unknown because the declared text carries no nullability signal.
        _ if node_text(operand, source) == "this" => true,
        "identifier" | "member_access_expression" => resolved_identifier_type(operand, source)
            .is_some_and(|type_text| {
                let trimmed = type_text.trim();
                trimmed != "var" && !trimmed.ends_with('?')
            }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S8969";

    #[test]
    fn s8969_non_nullable_parameter_flags() {
        let report = analyze_default(
            "class C {\n    void M(System.IDisposable reader) {\n        reader!.Dispose();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s8969_nullable_parameter_is_clean() {
        let report = analyze_default(
            "class C {\n    void M(System.IDisposable? reader) {\n        reader!.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s8969_this_flags() {
        let report =
            analyze_default("class C {\n    void M() {\n        this!.ToString();\n    }\n}\n");
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s8969_object_creation_flags() {
        let report = analyze_default(
            "class C {\n    void M() {\n        var x = new object()!;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s8969_non_nullable_local_flags() {
        let report = analyze_default(
            "class C {\n    void M() {\n        string s = \"x\";\n        s!.ToString();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s8969_nullable_local_is_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        string? s = null;\n        s!.ToString();\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s8969_var_local_is_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        var s = \"x\";\n        s!.ToString();\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s8969_invocation_result_is_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        Get()!.ToString();\n    }\n    object? Get() => null;\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s8969_null_literal_is_clean() {
        let report =
            analyze_default("class C {\n    void M() {\n        object x = null!;\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }
}
