use super::support::count_word_occurrences;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1481 — local variables nobody reads are noise. Discard
/// declarations (`_`) are exempt by convention.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["local_declaration_statement"])
        .into_iter()
        .filter(|statement| !has_modifier(&modifiers_of(*statement, source), "const"))
        .flat_map(|statement| collect_kinds(statement, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let text = node_text(name, source);
            (text != "_").then_some((name, text))
        })
        .filter(|(_, text)| count_word_occurrences(source, text) <= 1)
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
    fn s1481_treats_comment_mentions_as_reads() {
        let report = analyze_default(
            "class C\n{\n    int M()\n    {\n        // stale stays until the retry hook lands\n        int stale = Build();\n        return 0;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1481").is_empty());
    }

    #[test]
    fn s1481_matches_words_rather_than_substrings() {
        let report = analyze_default(
            "class C\n{\n    int M()\n    {\n        int page = Load();\n        Write(page);\n        int age = Compute();\n        return page + 0;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1481").len(), 1);
    }

    #[test]
    fn s1481_judges_whole_file_word_counts_not_scopes() {
        let shared = analyze_default(
            "class C\n{\n    int A()\n    {\n        int tmp = Build();\n        return 0;\n    }\n\n    int B()\n    {\n        int tmp = Build();\n        return tmp;\n    }\n}",
        );
        assert!(with_key(&shared, "csharpsquid:S1481").is_empty());

        let nested = analyze_default(
            "class C\n{\n    int M(bool gate)\n    {\n        if (gate)\n        {\n            int deep = Dig();\n        }\n        return 0;\n    }\n}\n",
        );
        assert_eq!(with_key(&nested, "csharpsquid:S1481").len(), 1);
    }
}
