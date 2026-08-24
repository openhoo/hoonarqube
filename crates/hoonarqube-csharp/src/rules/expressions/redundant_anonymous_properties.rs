use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3441 — `new { x = x }` spells out a name the compiler
/// already infers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["anonymous_object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        for (name, value) in anonymous_property_pairs(creation) {
            if !is_error_tainted(value) && node_text(name, source) == node_text(value, source) {
                issues.push(issue(
                    language,
                    "S3441",
                    "Use the shorthand property form; this assignment repeats the name.",
                    range_of(value),
                ));
            }
        }
    }
    issues
}

/// Initializer entries of an anonymous-object creation as `(name, value)`
/// pairs; shorthand entries yield no pair.
fn anonymous_property_pairs<'t>(creation: Node<'t>) -> Vec<(Node<'t>, Node<'t>)> {
    let mut cursor = creation.walk();
    let named: Vec<Node<'t>> = creation
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect();
    named
        .chunks(2)
        .filter_map(|pair| match pair {
            [name, value] => Some((*name, *value)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3441_distinct_property_values_have_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var o = new { Width = width };\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3441").is_empty());
    }

    #[test]
    fn s3441_flags_each_repeated_property_name_on_its_own_line() {
        let report = analyze_default(
            "class A\n{\n    object M(string name, int age)\n    {\n        return new\n        {\n            Name = name,\n            Age = age,\n            City = City,\n            Zip = Zip\n        };\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3441");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 9);
        assert_eq!(flagged[1].range.start.line, 10);
    }

    #[test]
    fn s3441_shorthand_initializers_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(string name, int age)\n    {\n        var o = new { name, age };\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3441").is_empty());
    }
}
