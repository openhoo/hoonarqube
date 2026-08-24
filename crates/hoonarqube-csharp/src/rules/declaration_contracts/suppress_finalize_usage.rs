use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::{
    banned_member_accesses, enclosing_type, member_declarations_of_kind,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3971 — `GC.SuppressFinalize` usage is tracked everywhere.
/// csharpsquid:S3234 additionally flags calls in finalizerless types where it
/// does nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for access in banned_member_accesses(root, source, "GC", &["SuppressFinalize"]) {
        issues.push(issue(
            language,
            "S3971",
            "Track uses of 'GC.SuppressFinalize'.",
            range_of(access),
        ));
        if enclosing_type(access).is_none_or(|type_node| !has_destructor(type_node)) {
            issues.push(issue(
                language,
                "S3234",
                "Only call 'GC.SuppressFinalize' when a finalizer is defined.",
                range_of(access),
            ));
        }
    }
    issues
}

/// Whether a type declares a finalizer.
fn has_destructor(type_node: Node<'_>) -> bool {
    !member_declarations_of_kind(type_node, "destructor_declaration").is_empty()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3971_tracks_calls_in_finalized_types() {
        let report = analyze_default(
            "class T\n{\n    ~T()\n    {\n    }\n\n    void Release()\n    {\n        GC.SuppressFinalize(this);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3971").len(), 1);
        assert!(with_key(&report, "csharpsquid:S3234").is_empty());
    }

    #[test]
    fn s3234_flags_finalizerless_types_once_per_call() {
        let once = analyze_default(
            "class T\n{\n    void Release()\n    {\n        GC.SuppressFinalize(this);\n    }\n}\n",
        );
        assert_eq!(with_key(&once, "csharpsquid:S3971").len(), 1);
        assert_eq!(with_key(&once, "csharpsquid:S3234").len(), 1);

        let twice = analyze_default(
            "class T\n{\n    void Release(bool again)\n    {\n        GC.SuppressFinalize(this);\n        if (again)\n        {\n            GC.SuppressFinalize(this);\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&twice, "csharpsquid:S3971").len(), 2);
        assert_eq!(with_key(&twice, "csharpsquid:S3234").len(), 2);
    }

    #[test]
    fn s3234_spares_other_gc_members() {
        let report = analyze_default(
            "class T\n{\n    void Sweep()\n    {\n        GC.Collect();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3971").is_empty());
        assert!(with_key(&report, "csharpsquid:S3234").is_empty());
    }
}
