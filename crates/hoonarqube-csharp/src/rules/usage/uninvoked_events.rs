use super::support::{direct_variable_declarators, scoped_identifier_is_referenced};
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3264 — events nobody raises can never inform anybody.
/// Subscriptions alone do not raise; this in-file heuristic only certifies
/// events whose name appears nowhere beyond its declaration.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let declared: Vec<(Node<'_>, Node<'_>, &str)> =
        collect_kinds(root, &["event_field_declaration"])
            .into_iter()
            .filter(|declaration| !is_error_tainted(*declaration))
            .flat_map(direct_variable_declarators)
            .filter_map(|declarator| {
                let name = declarator.child_by_field_name("name")?;
                let owner = ancestors_of(declarator)
                    .find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))?;
                Some((owner, name, node_text(name, source)))
            })
            .collect();
    if declared.is_empty() {
        return Vec::new();
    }
    let mut referenced = std::collections::HashMap::new();
    declared
        .into_iter()
        .filter(|(owner, _, name)| {
            !*referenced
                .entry((owner.id(), *name))
                .or_insert_with(|| scoped_identifier_is_referenced(*owner, name, source))
        })
        .map(|(_, name_node, name)| {
            issue(
                language,
                "S3264",
                format!("Remove the unused event '{name}' or invoke it."),
                range_of(name_node, source),
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
    fn s3264_keeps_verdicts_inside_each_declaring_type() {
        let both_silent = analyze_default(
            "class P\n{\n    event System.EventHandler Ping;\n}\n\nclass Q\n{\n    event System.EventHandler Ping;\n}\n",
        );
        assert_eq!(with_key(&both_silent, "csharpsquid:S3264").len(), 2);

        let one_raised = analyze_default(
            "class P\n{\n    event System.EventHandler Ping;\n\n    void Raise()\n    {\n        Ping(this, System.EventArgs.Empty);\n    }\n}\n\nclass Q\n{\n    event System.EventHandler Ping;\n}\n",
        );
        let flagged = with_key(&one_raised, "csharpsquid:S3264");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 13);
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

    #[test]
    fn s3264_ignores_comments_and_strings_with_the_event_name() {
        let report = analyze_default(
            "class C\n{\n    event System.EventHandler Done;\n    string Note() => \"Done\"; // Done later\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3264").len(), 1);
    }

    #[test]
    fn s3264_does_not_treat_shadowing_locals_as_event_usage() {
        let report = analyze_default(
            "class C\n{\n    event System.EventHandler Done;\n    public void M()\n    {\n        System.Action Done = () => { };\n        Done();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3264").len(), 1);
    }
}
