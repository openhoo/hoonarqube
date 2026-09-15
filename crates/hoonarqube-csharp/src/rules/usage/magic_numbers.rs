use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::integer_literal_value;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

fn canonical_number_text(text: &str) -> String {
    let unsuffixed = text.trim_end_matches(['f', 'F', 'd', 'D', 'm', 'M', 'u', 'U', 'l', 'L']);
    let normalized = unsuffixed.replace('_', "");
    let radix_prefixed = ["0x", "0X", "0b", "0B"]
        .iter()
        .any(|prefix| normalized.starts_with(prefix));
    if !radix_prefixed && let Some(value) = integer_literal_value(text) {
        return value.to_string();
    }
    normalized
        .parse::<f64>()
        .map_or(normalized.clone(), |value| value.to_string())
}

/// csharpsquid:S109 — numbers beyond -1/0/1 deserve names. The catalog scope
/// is MAIN; test-scoped files are silenced centrally in `analyze`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["integer_literal", "real_literal"])
        .into_iter()
        .filter(|literal| !is_error_tainted(*literal))
        .filter(|literal| {
            !magic_number_exempt(*literal, source)
                && !is_small_allowed_number(node_text(*literal, source))
        })
        .map(|literal| {
            let value = canonical_number_text(node_text(literal, source));
            issue(
                language,
                "S109",
                format!("Assign this magic number '{value}' to a well-named variable or constant, and use that instead."),
                range_of(literal, source),
            )
        })
        .collect()
}

/// Whether a numeric literal's value is exactly -1, 0, or 1.
#[allow(clippy::float_cmp)] // 0.0/1.0 are exactly representable; exact match is the intent
fn is_small_allowed_number(text: &str) -> bool {
    if let Some(value) = integer_literal_value(text) {
        return value <= 1;
    }
    // Real literals: compare parsed values; 0.0 and 1.0 are exactly
    // representable, so equality stays deterministic across spellings
    // (exponents, suffixes, digit separators).
    let base = text
        .strip_suffix(['f', 'F', 'd', 'D', 'm', 'M'])
        .unwrap_or(text);
    base.replace('_', "")
        .parse::<f64>()
        .is_ok_and(|value| value == 0.0 || value == 1.0)
}

/// Contexts where even large numbers are not magic, mirroring the reference
/// rule's exception set: variable declarations (locals, fields, `fixed`/`for`
/// initializers — constants included), parameter defaults, enum members,
/// `GetHashCode` bodies, `#pragma warning` directive numbers, property
/// getters and initializers, single-digit collection-size comparisons, and
/// constructor/named/time-style/attribute arguments.
fn magic_number_exempt(literal: Node<'_>, source: &str) -> bool {
    let Some(direct) = literal.parent() else {
        return false;
    };
    // Exception shapes where the literal's direct parent decides.
    match direct.kind() {
        // Directive argument text, e.g. `#pragma warning disable 0618`.
        "preproc_pragma" => return true,
        "binary_expression" if is_comparison_operator(direct) => {
            if is_collection_size_comparison(literal, direct, source) {
                return true;
            }
        }
        "argument" | "attribute_argument" if is_tolerated_argument(direct, source) => {
            return true;
        }
        _ => {}
    }
    // Named-value ancestors anywhere between the literal and its container.
    let mut ancestor = literal.parent();
    while let Some(node) = ancestor {
        match node.kind() {
            "variable_declaration" | "enum_member_declaration" | "parameter" => return true,
            "property_declaration" => {
                // Getter `return` values and auto-property initializers are
                // named values; the initializer is the literal's direct
                // parent (`field('value', …)`) without a value clause.
                return match literal.parent().map(|parent| (parent.kind(), parent.id())) {
                    Some(("return_statement" | "equals_value_clause", _)) => true,
                    Some((_, parent_id)) => parent_id == node.id(),
                    None => false,
                };
            }
            "method_declaration" => {
                return node
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == "GetHashCode");
            }
            _ => {}
        }
        ancestor = node.parent();
    }
    false
}

fn is_comparison_operator(binary: Node<'_>) -> bool {
    let Some(operator) = binary.child_by_field_name("operator") else {
        return false;
    };
    matches!(
        binary_operator_text(operator),
        "==" | "!=" | "<" | "<=" | ">" | ">="
    )
}

/// The operator child is an anonymous token whose kind is the operator text.
fn binary_operator_text(operator: Node<'_>) -> &str {
    if operator.is_named() {
        ""
    } else {
        operator.kind()
    }
}

/// Single digits may compare against a collection-size member (`Length`,
/// `Count`, `Size`, or a `.Count()` call) — the canonical bounds checks.
fn is_collection_size_comparison(literal: Node<'_>, comparison: Node<'_>, source: &str) -> bool {
    let text = node_text(literal, source).replace('_', "");
    let Ok(single_digit) = text.parse::<u8>() else {
        return false;
    };
    if single_digit > 9 {
        return false;
    }
    let mut cursor = comparison.walk();
    comparison
        .children(&mut cursor)
        .filter(|child| child.is_named() && child.id() != literal.id())
        .any(|operand| {
            member_access_name(operand, source)
                .is_some_and(|name| matches!(name, "Length" | "Count" | "Size"))
        })
}

/// Rightmost member name of a `x.Y`, `x.Y()`, or `x.Y().Z` chain.
fn member_access_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "member_access_expression" => node
            .child_by_field_name("name")
            .map(|name| node_text(name, source)),
        "invocation_expression" => node
            .child_by_field_name("function")
            .and_then(|function| member_access_name(function, source)),
        _ => None,
    }
}

/// Called-name lookup that also accepts a bare identifier callee, matching
/// the reference `GetIdentifier` resolution for `FromX(…)` factory calls.
fn called_name<'a>(function: Node<'a>, source: &'a str) -> Option<&'a str> {
    match function.kind() {
        "identifier" => Some(node_text(function, source)),
        _ => member_access_name(function, source),
    }
}

/// Named arguments, constructor arguments, `TimeSpan.FromX(…)`-style factory
/// calls, and attribute arguments (named or single-valued) keep their numbers.
fn is_tolerated_argument(argument: Node<'_>, source: &str) -> bool {
    if argument.child_by_field_name("name").is_some() {
        // Named method/attribute arguments carry their meaning in the name.
        return true;
    }
    if argument.kind() == "attribute_argument" {
        return is_single_attribute_argument(argument);
    }
    let Some(list) = argument
        .parent()
        .filter(|list| list.kind() == "argument_list")
    else {
        return false;
    };
    let Some(call) = list.parent() else {
        return false;
    };
    match call.kind() {
        "object_creation_expression" => true,
        "invocation_expression" => call
            .child_by_field_name("function")
            .and_then(|function| called_name(function, source))
            .is_some_and(|name| name.starts_with("From")),
        _ => false,
    }
}

fn is_single_attribute_argument(argument: Node<'_>) -> bool {
    argument
        .parent()
        .filter(|list| list.kind() == "attribute_argument_list")
        .is_some_and(|list| {
            let mut cursor = list.walk();
            list.children(&mut cursor)
                .filter(|child| child.kind() == "attribute_argument")
                .count()
                == 1
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s109_flags_return_and_assignment_contexts() {
        let report = analyze_default(
            "class C\n{\n    int total;\n    int M()\n    {\n        total = 42;\n        return 41 + total;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S109").len(), 2);
    }

    #[test]
    fn s109_spares_declarations_defaults_enums_and_pragmas() {
        let report = analyze_default(
            "class C\n{\n    int f = 800;\n    const int Cap = 400;\n    int P { get; set; } = 250;\n    enum E { Max = 600 }\n    void M(int retries = 7)\n    {\n        int plain = 11;\n#pragma warning disable 0618\n        Step();\n#pragma warning restore 0618\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S109").is_empty());
    }

    #[test]
    fn s109_spares_hash_code_property_returns_and_size_comparisons() {
        let report = analyze_default(
            "class C\n{\n    public override int GetHashCode() => seed * 31;\n    int Limited\n    {\n        get { return 250; }\n    }\n    bool Two(string name)\n    {\n        return name.Length == 2;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S109").len(), 0);
    }

    #[test]
    fn s109_spares_ctor_named_and_factory_arguments() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var map = new Dictionary<int, int>(41);\n        Step(amount: 42);\n        var wait = TimeSpan.FromMinutes(5);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S109").is_empty());
    }

    #[test]
    fn s109_keeps_numbers_inside_deeper_expressions_magic() {
        let report = analyze_default(
            "class C\n{\n    bool Check(string name)\n    {\n        return (name.Length == (2)) && Sum(2 + 2) > 1;\n    }\n    int Sum(int value) => value;\n}\n",
        );
        // `(name.Length == (2))` — the 2 is nested, not a direct operand;
        // `Sum(2 + 2)` arguments hold two nested literals; `> 1` is allowed.
        let flagged = with_key(&report, "csharpsquid:S109");
        assert_eq!(flagged.len(), 3);
    }
}
