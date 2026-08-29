use super::support::{enclosing_callable, enclosing_type};
use crate::CsLanguage;
use crate::cst::{
    attributes_of, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::modifiers::has_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3265 — bitwise operations need `[Flags]` enums.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let enum_types = non_flags_enum_names(root, source);
    if enum_types.is_empty() {
        return Vec::new();
    }
    let typed_values = typed_values(root, source);
    let mut issues = Vec::new();
    let mut expressions = collect_kinds(root, &["binary_expression"]);
    expressions.extend(collect_kinds(root, &["assignment_expression"]));
    for expression in expressions {
        if is_error_tainted(expression) || bitwise_operator(expression).is_none() {
            continue;
        }
        if let Some(enum_name) = touched_enum(expression, source, &enum_types, &typed_values) {
            let mut cursor = expression.walk();
            let operator = expression
                .children(&mut cursor)
                .find(|child| matches!(child.kind(), "|" | "&" | "^" | "|=" | "&=" | "^="))
                .unwrap_or(expression);
            issues.push(issue(
                language,
                "S3265",
                format!(
                    "Mark enum '{enum_name}' with 'Flags' attribute or remove this bitwise operation."
                ),
                range_of(operator, source),
            ));
        }
    }
    issues
}

/// Non-`[Flags]` enum type names declared in the file plus the names of
/// their members.
fn non_flags_enum_names<'a>(root: Node<'a>, source: &'a str) -> std::collections::HashSet<&'a str> {
    let mut types = std::collections::HashSet::new();
    for enum_node in collect_kinds(root, &["enum_declaration"]) {
        if has_attribute(&attributes_of(enum_node, source), "Flags") {
            continue;
        }
        if let Some(name) = enum_node.child_by_field_name("name") {
            types.insert(node_text(name, source));
        }
    }
    types
}

struct TypedValue<'t> {
    name: String,
    type_name: String,
    scope: Node<'t>,
}

fn typed_values<'t>(root: Node<'t>, source: &str) -> Vec<TypedValue<'t>> {
    let mut values = Vec::new();
    for parameter in collect_kinds(root, &["parameter"]) {
        if let Some((type_node, name, scope)) = parameter
            .child_by_field_name("type")
            .zip(parameter.child_by_field_name("name"))
            .zip(enclosing_callable(parameter))
            .map(|((type_node, name), scope)| (type_node, name, scope))
        {
            values.push(TypedValue {
                name: node_text(name, source).to_string(),
                type_name: simple_name(node_text(type_node, source)).to_string(),
                scope,
            });
        }
    }
    for declarator in collect_kinds(root, &["variable_declarator"]) {
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let Some(declaration) = declarator.parent() else {
            continue;
        };
        let Some(type_node) = declaration.child_by_field_name("type") else {
            continue;
        };
        let Some(scope) = enclosing_callable(declarator).or_else(|| enclosing_type(declarator))
        else {
            continue;
        };
        values.push(TypedValue {
            name: node_text(name, source).to_string(),
            type_name: simple_name(node_text(type_node, source)).to_string(),
            scope,
        });
    }
    values
}

fn touched_enum<'a>(
    expression: Node<'_>,
    source: &'a str,
    enum_types: &std::collections::HashSet<&'a str>,
    typed_values: &[TypedValue<'_>],
) -> Option<&'a str> {
    for identifier in collect_kinds(expression, &["identifier"]) {
        let name = node_text(identifier, source);
        if enum_types.contains(name)
            && identifier
                .parent()
                .is_some_and(|parent| parent.kind() == "member_access_expression")
        {
            return Some(name);
        }
        let site = identifier.byte_range();
        if let Some(value) = typed_values
            .iter()
            .filter(|value| {
                value.name == name
                    && value.scope.start_byte() <= site.start
                    && value.scope.end_byte() >= site.end
            })
            .min_by_key(|value| value.scope.end_byte() - value.scope.start_byte())
            && enum_types.contains(value.type_name.as_str())
        {
            return enum_types
                .iter()
                .find(|enum_name| **enum_name == value.type_name)
                .copied();
        }
    }
    None
}

/// The bitwise operator of a binary or assignment expression.
fn bitwise_operator(expression: Node<'_>) -> Option<&'static str> {
    const OPERATORS: [&str; 6] = ["|", "&", "^", "|=", "&=", "^="];
    let mut cursor = expression.walk();
    let kind = expression
        .children(&mut cursor)
        .find(|child| !child.is_named())?
        .kind();
    OPERATORS
        .iter()
        .find(|operator| **operator == kind)
        .copied()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3265_flags_member_only_bitwise_expression() {
        let report = analyze_default(
            "enum Style\n{\n    Bold,\n    Italic\n}\nclass C\n{\n    int Mix()\n    {\n        return (int)(Style.Bold & Style.Italic);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3265");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 10);
    }

    #[test]
    fn s3265_ignores_flags_attributed_enums() {
        let report = analyze_default(
            "[Flags]\nenum Mask\n{\n    A,\n    B\n}\nclass C\n{\n    int Mix(Mask mask)\n    {\n        return (int)(mask | Mask.A);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3265").is_empty());
    }

    #[test]
    fn s3265_ignores_equality_on_enum_values() {
        let report = analyze_default(
            "enum Color\n{\n    Red,\n    Green\n}\nclass C\n{\n    bool Same(Color color)\n    {\n        return color == Color.Red;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3265").is_empty());
    }

    #[test]
    fn s3265_flags_compound_assignment_operator() {
        let report = analyze_default(
            "enum Mode\n{\n    On,\n    Off\n}\nclass C\n{\n    void Turn(Mode mode)\n    {\n        mode |= Mode.On;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3265");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 10);
    }

    #[test]
    fn s3265_reports_each_bitwise_operation_distinctly() {
        let report = analyze_default(
            "enum Tone\n{\n    High,\n    Low\n}\nclass C\n{\n    void Both(Tone tone)\n    {\n        tone |= Tone.High;\n        tone &= Tone.Low;\n    }\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S3265")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![10, 11]);
    }

    #[test]
    fn s3265_does_not_leak_typed_names_between_methods() {
        let report = analyze_default(
            "enum Mode { On, Off }\nclass C\n{\n    int EnumBits(Mode value) => (int)(value | Mode.On);\n    int IntegerBits(int value) => value | 1;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3265");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s3265_reports_the_enum_actually_used() {
        let report = analyze_default(
            "enum Alpha { A, B }\nenum Beta { A, B }\nclass C\n{\n    int Mix(Beta value) => (int)(value | Beta.A);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3265");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Beta'"));
    }
}
