use super::support::{direct_variable_declarators, local_is_referenced};
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1481 — local variables nobody reads are noise. Discard
/// declarations (`_`) are exempt by convention.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["local_declaration_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter(|statement| !has_modifier(&modifiers_of(*statement, source), "const"))
        .flat_map(direct_variable_declarators)
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let text = node_text(name, source);
            (text != "_").then_some((name, text))
        })
        .filter(|(name, text)| !local_is_referenced(*name, text, source))
        .map(|(name_node, name)| {
            issue(
                language,
                "S1481",
                format!("Remove the unused local variable '{name}'."),
                range_of(name_node, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1481_flags_only_the_dead_declarator_of_a_statement() {
        let report = analyze_default(
            "class C\n{\n    int M()\n    {\n        int used = 1, stale = 2;\n        return used;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1481").len(), 1);
    }

    #[test]
    fn s1481_ignores_comment_mentions() {
        let report = analyze_default(
            "class C\n{\n    int M()\n    {\n        // stale stays until the retry hook lands\n        int stale = Build();\n        return 0;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1481").len(), 1);
    }

    #[test]
    fn s1481_matches_words_rather_than_substrings() {
        let report = analyze_default(
            "class C\n{\n    int M()\n    {\n        int page = Load();\n        Write(page);\n        int age = Compute();\n        return page + 0;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1481").len(), 1);
    }

    #[test]
    fn s1481_keeps_usage_inside_each_lexical_scope() {
        let shared = analyze_default(
            "class C\n{\n    int A()\n    {\n        int tmp = Build();\n        return 0;\n    }\n\n    int B()\n    {\n        int tmp = Build();\n        return tmp;\n    }\n}",
        );
        let flagged = with_key(&shared, "csharpsquid:S1481");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let nested = analyze_default(
            "class C\n{\n    int M(bool gate)\n    {\n        if (gate)\n        {\n            int deep = Dig();\n        }\n        return 0;\n    }\n}\n",
        );
        assert_eq!(with_key(&nested, "csharpsquid:S1481").len(), 1);
    }

    #[test]
    fn s1481_does_not_collect_nested_initializer_declarations_twice() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        System.Action outer = () =>\n        {\n            int inner = Build();\n        };\n        outer();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1481");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'inner'"));
    }

    #[test]
    fn s1481_does_not_treat_member_access_names_as_local_reads() {
        let report = analyze_default(
            "class C\n{\n    int value;\n    void M()\n    {\n        int value = Build();\n        this.value = 1;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1481").len(), 1);
    }
}
