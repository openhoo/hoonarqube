use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{member_declarations_of_kind, overloaded_operator};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3875 — overloading `==` on reference types invites identity
/// confusion; structs are exempt.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        for declaration in member_declarations_of_kind(class_declaration, "operator_declaration") {
            if is_error_tainted(declaration) || overloaded_operator(declaration) != Some("==") {
                continue;
            }
            issues.push(issue(
                language,
                "S3875",
                "Do not overload the equality operator on this reference type.",
                range_of(declaration),
            ));
        }
    }
    let _ = source;
    issues
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3875_flags_nested_class_operator_equals() {
        let report = analyze_default(
            "class Outer\n{\n    class Inner\n    {\n        public static bool operator ==(Inner a, Inner b) => true;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3875").len(), 1);
    }

    #[test]
    fn s3875_counts_each_offending_class_once() {
        let report = analyze_default(
            "class A\n{\n    public static bool operator ==(A x, A y) => true;\n}\n\nclass B\n{\n    public static bool operator ==(B x, B y) => true;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3875").len(), 2);

        let arithmetic = analyze_default(
            "class Money\n{\n    public static Money operator +(Money a, Money b) => a;\n}\n",
        );
        assert!(with_key(&arithmetic, "csharpsquid:S3875").is_empty());
    }
}
