use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::first_named_child;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6618 — `FormattableString` flows allocate; `string.Create`
/// formats directly into place.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter(|node| {
            first_named_child(*node).is_some_and(|receiver| {
                node_text(receiver, source)
                    .trim()
                    .ends_with("FormattableString")
            })
        })
        .map(|node| {
            let anchor = node.child_by_field_name("name").unwrap_or(node);
            issue(
                language,
                "S6618",
                "Use \"string.Create\" instead of \"FormattableString\".",
                range_of(anchor, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6618_flags_qualified_formattable_string_receivers() {
        let report = analyze_default(
            "class C\n{\n    string Text()\n    {\n        return System.FormattableString.Invariant($\"y{2}\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6618").len(), 1);
    }

    #[test]
    fn s6618_plain_interpolated_strings_stay_unflagged() {
        let report = analyze_default(
            "class C\n{\n    string Text()\n    {\n        return $\"y{2}\";\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6618").is_empty());
    }
}
