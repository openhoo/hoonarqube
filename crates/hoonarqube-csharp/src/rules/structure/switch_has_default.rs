use super::support::{section_has_default, switch_body_of, switch_sections_of};
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S131 — every `switch` carries a `default` clause.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let has_default = switch_body_of(switch_statement)
            .map(switch_sections_of)
            .is_some_and(|sections| sections.into_iter().any(section_has_default));
        if !has_default {
            let keyword = collect_kinds(switch_statement, &["switch"])
                .into_iter()
                .next()
                .unwrap_or(switch_statement);
            issues.push(issue(
                language,
                "S131",
                "Add a 'default' clause to this 'switch' statement.",
                range_of(keyword, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s131_nested_switch_default_does_not_satisfy_outer_switch() {
        let report = analyze_default(
            "class C\n{\n    void M(int outer, int inner)\n    {\n        switch (outer)\n        {\n            case 1:\n                switch (inner)\n                {\n                    default:\n                        break;\n                }\n                break;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S131");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
}
