use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_function};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4040 — normalization belongs in uppercase; lowercased
/// strings compare and hash differently across cultures.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| callee_name(*call, source) == Some("ToLowerInvariant"))
        .map(|call| {
            issue(
                language,
                "S4040",
                "Change this normalization to 'ToUpperInvariant()'.",
                range_of(
                    invocation_function(call)
                        .and_then(|function| function.child_by_field_name("name"))
                        .unwrap_or(call),
                    source,
                ),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4040_flags_lowercasing_at_the_end_of_a_chain() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        key = name.Trim().ToLower();\n        slug = raw.ToLowerInvariant().Replace(\" \", \"-\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4040").len(), 1);
    }
}
