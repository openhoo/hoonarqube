//! `java:S1117` — local variables should not shadow class fields.
//!
//! Contract pinned against the live SonarQube 26.8 Community reference
//! (rule show: scope ALL, MAJOR CODE_SMELL, no parameters; oracle: the
//! pinned `gson` scan with 92 findings). The reference reports every local
//! variable declaration whose simple name equals a field of any type in the
//! enclosing chain of the declaration site — the immediate type first, then
//! outer and anonymous types — anchoring on the declared name and naming the
//! matched field's declaration line in the same file. Silent: method,
//! catch, and lambda parameters hiding fields, locals shadowing other
//! locals, and inherited members from supertypes outside the compilation
//! unit (the frontend makes no classpath assumptions).

use crate::support::{LineIndex, collect_kinds, node_text};
use hoonarqube_ir::{Issue, Range};
use tree_sitter::Node;

pub(crate) fn check(root: Node<'_>, source: &str, lines: &LineIndex) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(root, &["local_variable_declaration"]) {
        let mut cursor = declaration.walk();
        let declarators: Vec<Node<'_>> = declaration
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "variable_declarator")
            .collect();
        for declarator in declarators {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(field_line) = hiding_field_line(name, source) else {
                continue;
            };
            let local_name = node_text(name, source);
            issues.push(Issue::new(
                "java:S1117",
                format!("Rename \"{local_name}\" which hides the field declared at line {field_line}."),
                range_of_name(name, source, lines),
            ));
        }
    }
    issues
}

/// Walks the type bodies enclosing `name` from the innermost outward and
/// returns the declaration line of the first field with the same simple name.
fn hiding_field_line(name: Node<'_>, source: &str) -> Option<u32> {
    let target = node_text(name, source);
    let mut ancestor = name.parent();
    while let Some(body) = ancestor {
        if matches!(body.kind(), "class_body" | "interface_body" | "enum_body")
            && let Some(line) = field_line_in_body(body, target, source)
        {
            return Some(line);
        }
        ancestor = body.parent();
    }
    None
}

fn field_line_in_body(body: Node<'_>, target: &str, source: &str) -> Option<u32> {
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        let line = match child.kind() {
            "field_declaration" | "constant_declaration" => declarator_line(child, target, source),
            "enum_constant" => child
                .child_by_field_name("name")
                .filter(|name| node_text(*name, source) == target)
                .map(|name| line_of(name)),
            "enum_body_declarations" => field_line_in_body(child, target, source),
            _ => None,
        };
        if line.is_some() {
            return line;
        }
    }
    None
}

fn declarator_line(declaration: Node<'_>, target: &str, source: &str) -> Option<u32> {
    let mut cursor = declaration.walk();
    for declarator in declaration
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "variable_declarator")
    {
        if let Some(name) = declarator.child_by_field_name("name")
            && node_text(name, source) == target
        {
            return Some(line_of(name));
        }
    }
    None
}

fn line_of(node: Node<'_>) -> u32 {
    u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX)
}

fn range_of_name(name: Node<'_>, source: &str, lines: &LineIndex) -> Range {
    lines.range(source, name.start_byte(), name.end_byte())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::parse;
    fn findings(source: &str) -> Vec<Issue> {
        let tree = parse(source).expect("valid Java fixture");
        let lines = LineIndex::new(source);
        check(tree.root_node(), source, &lines)
    }

    fn first_message(source: &str) -> String {
        findings(source).remove(0).message
    }

    #[test]
    fn reports_local_hiding_field_with_reference_line() {
        let source = "class A {\n  int value;\n  void f() {\n    int value = 1;\n  }\n}";
        assert_eq!(findings(source).len(), 1);
        assert_eq!(
            first_message(source),
            "Rename \"value\" which hides the field declared at line 2."
        );
    }

    #[test]
    fn local_in_nested_type_hides_outer_field() {
        let source = concat!(
            "class Outer {\n",
            "  Gson gson = new Gson();\n",
            "  Runnable r = new Runnable() {\n",
            "    public void run() {\n",
            "      var gson = new Gson();\n",
            "    }\n",
            "  };\n",
            "}"
        );
        assert_eq!(findings(source).len(), 1);
        assert_eq!(
            first_message(source),
            "Rename \"gson\" which hides the field declared at line 2."
        );
    }

    #[test]
    fn every_declarator_in_multi_declaration_is_checked() {
        let source =
            "class A { int a; int b; void f() { int keep = 1, a = 2, b = 3; } }";
        let findings = findings(source);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|issue| issue.message.contains("\"a\"")
            || issue.message.contains("\"b\"")));
    }

    #[test]
    fn parameters_catch_and_lambda_bindings_stay_silent() {
        let source = concat!(
            "class A {\n",
            "  int value;\n",
            "  void f(int value) {}\n",
            "  void g() {\n",
            "    try {} catch (RuntimeException value) {}\n",
            "    Runnable r = () -> { int value = 1; };\n",
            "  }\n",
            "}"
        );
        // The lambda body declares a genuine local inside the class scope and
        // is reported; method and catch parameters are not local variables.
        let findings = findings(source);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("line 2."));
    }

    #[test]
    fn local_shadowing_local_and_clean_controls_stay_silent() {
        let source = concat!(
            "class A {\n",
            "  int value;\n",
            "  void f() {\n",
            "    int inner = 1;\n",
            "    {\n",
            "      int inner = 2;\n",
            "    }\n",
            "    int other = 3;\n",
            "  }\n",
            "}"
        );
        assert!(findings(source).is_empty());
    }
}
