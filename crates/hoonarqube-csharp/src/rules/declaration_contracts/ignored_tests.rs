use super::support::attribute_applications;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1607 — ignored tests silently stop guarding behavior.
/// NUnit/MSTest `[Ignore]` spellings match their final name segment
/// (`NUnit.Framework.Ignore` included); xUnit silences a test through a
/// `Skip` named argument on `[Fact]`/`[Theory]`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    attribute_applications(root, source)
        .into_iter()
        .filter_map(|(name, arguments, node)| {
            let silenced = match final_segment(name) {
                "Ignore" | "IgnoreAttribute" => arguments.is_none(),
                "Fact" | "Theory" => carries_skip(arguments, source),
                _ => false,
            };
            silenced.then(|| {
                issue(
                    language,
                    "S1607",
                    "Either remove this 'Ignore' attribute or add an explanation about why this test is ignored.",
                    range_of(node, source),
                )
            })
        })
        .collect()
}

/// Last segment of a possibly qualified attribute name
/// (`NUnit.Framework.Ignore` → `Ignore`).
fn final_segment(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

/// Whether an argument list carries a `Skip` named argument. The grammar
/// binds both `Skip = …` and `Skip: …` into `attribute_argument`'s `name`
/// field; an `assignment_expression` child stays accepted as a fallback
/// for the other parse resolution.
fn carries_skip(arguments: Option<Node<'_>>, source: &str) -> bool {
    arguments.is_some_and(|arguments| {
        collect_kinds(arguments, &["attribute_argument"])
            .into_iter()
            .any(|argument| {
                named_skip(&argument, source)
                    || collect_kinds(argument, &["assignment_expression"])
                        .into_iter()
                        .any(|assignment| {
                            assignment
                                .child_by_field_name("left")
                                .is_some_and(|left| node_text(left, source) == "Skip")
                        })
            })
    })
}

fn named_skip(argument: &Node<'_>, source: &str) -> bool {
    argument
        .child_by_field_name("name")
        .is_some_and(|name| node_text(name, source) == "Skip")
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1607_flags_long_form_ignore_annotations() {
        let report =
            analyze_default("class Suite\n{\n    [IgnoreAttribute]\n    void T() { }\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S1607").len(), 1);

        let categorized =
            analyze_default("class Suite\n{\n    [Category(\"slow\")]\n    void T() { }\n}\n");
        assert!(with_key(&categorized, "csharpsquid:S1607").is_empty());
    }

    #[test]
    fn s1607_accepts_reasoned_ignore_and_flags_bare_ignore() {
        let report = analyze_default(
            "class Suite\n{\n    [Ignore(\"flaky\")]\n    void A() { }\n\n    [Ignore]\n    void B() { }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1607").len(), 1);
    }

    #[test]
    fn s1607_flags_xunit_skip_and_qualified_ignore_spellings() {
        let report = analyze_default(
            "class Suite\n{\n    [Xunit.Fact(Skip = \"later\")]\n    void A() { }\n\n    [Theory(Skip: \"soon\")]\n    void B() { }\n\n    [Fact]\n    void C() { }\n\n    [NUnit.Framework.Ignore]\n    void D() { }\n\n    [Category(\"slow\")]\n    void E() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1607");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 6);
        assert_eq!(flagged[2].range.start.line, 12);
    }
}
