use super::support::count_word_occurrences;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3264 — events nobody raises can never inform anybody.
/// Subscriptions alone do not raise; this in-file heuristic only certifies
/// events whose name appears nowhere beyond its declaration.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let declared: Vec<(Node<'_>, &str)> = collect_kinds(root, &["event_field_declaration"])
        .into_iter()
        .flat_map(|declaration| collect_kinds(declaration, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            Some((declarator, node_text(name, source)))
        })
        .collect();
    if declared.is_empty() {
        return Vec::new();
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (_, name) in &declared {
        *counts.entry(name).or_insert(0) += 1;
    }
    declared
        .into_iter()
        .filter(|(_, name)| count_word_occurrences(source, name) <= counts[name])
        .map(|(declarator, name)| {
            issue(
                language,
                "S3264",
                format!("Remove the unused event '{name}' or invoke it."),
                range_of(declarator, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3264_flags_every_silent_declarator_of_a_list() {
        let report = analyze_default("class C\n{\n    event System.EventHandler A, B;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3264");
        assert_eq!(flagged.len(), 2);
        assert!(flagged.iter().any(|issue| issue.message.contains("'A'")));
        assert!(flagged.iter().any(|issue| issue.message.contains("'B'")));
    }

    #[test]
    fn s3264_shares_one_verdict_between_duplicate_names() {
        let both_silent = analyze_default(
            "class P\n{\n    event System.EventHandler Ping;\n}\n\nclass Q\n{\n    event System.EventHandler Ping;\n}\n",
        );
        assert_eq!(with_key(&both_silent, "csharpsquid:S3264").len(), 2);

        let one_raised = analyze_default(
            "class P\n{\n    event System.EventHandler Ping;\n\n    void Raise()\n    {\n        Ping(this, System.EventArgs.Empty);\n    }\n}\n\nclass Q\n{\n    event System.EventHandler Ping;\n}\n",
        );
        assert!(with_key(&one_raised, "csharpsquid:S3264").is_empty());
    }

    #[test]
    fn s3264_ignores_accessor_style_event_declarations() {
        let report = analyze_default(
            "class C\n{\n    event System.EventHandler Custom\n    {\n        add { }\n        remove { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3264").is_empty());
    }

    #[test]
    fn s3264_audits_static_event_fields_like_instance_ones() {
        let report = analyze_default("class C\n{\n    static event System.EventHandler Tick;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3264");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Tick'"));
    }
}
