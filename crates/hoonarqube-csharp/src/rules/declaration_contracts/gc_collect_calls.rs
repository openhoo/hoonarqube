use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1215 — explicit `GC.Collect` calls fight the garbage
/// collector's own heuristics.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "GC", &["Collect"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S1215",
                "Refactor the code to remove this use of 'GC.Collect'.",
                range_of(access.child_by_field_name("name").unwrap_or(access), source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1215_flags_short_and_qualified_gc_receivers() {
        let report = analyze_default(
            "class C\n{\n    void Clean()\n    {\n        GC.Collect();\n        System.GC.Collect(2);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1215").len(), 2);
    }

    #[test]
    fn s1215_other_collect_calls_stay_unflagged() {
        let report = analyze_default(
            "class C\n{\n    void Clean()\n    {\n        bin.Collect();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1215").is_empty());
    }
}
