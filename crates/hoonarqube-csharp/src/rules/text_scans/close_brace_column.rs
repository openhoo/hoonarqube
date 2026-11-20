use crate::CsLanguage;
use crate::cst::{issue, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1109 — closing braces sit at the start of their line.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() == "}"
            // Initializers can contain executable blocks; exempt only their own delimiter.
            && !node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "initializer_expression" | "anonymous_object_creation_expression"
                )
            })
            && source[..node.start_byte()]
                .rsplit('\n')
                .next()
                .is_some_and(|prefix| {
                    !prefix.contains('{')
                        && prefix.chars().any(|character| !character.is_whitespace())
                })
        {
            issues.push(issue(
                language,
                "S1109",
                "Move this closing curly brace to the next line.",
                range_of(node, source),
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::analyze_default;
    use hoonarqube_ir::{Issue, Pos, Range};

    // The installed Sonar analyzer exempts all five initializer delimiters,
    // while retaining the ordinary multiline block at 18:22–18:23.
    const CONTROL: &str = r"using System.Collections.Generic;
namespace Scope;
class Cases
{
    int[] A = new[] {
        1, 2 };
    Dictionary<int, int> D = new() {
        [1] = 2 };
    List<int> L = new() {
        1, 2 };
    Cases O = new Cases {
        Value = 1 };
    object Anonymous = new {
        X = 1 };
    public int Value { get; set; }
    void Block()
    {
        _ = A.Length; }
    void Good()
    {
        _ = A.Length;
    }
    void Inline() { _ = A.Length; }
}
";
    const NESTED: &str = r"using System;
namespace Scope;
class Nested
{
    Func<int>[] F = {
        () => {
            return 1; } };
}
";

    fn findings(source: &str) -> Vec<Issue> {
        analyze_default(source)
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "csharpsquid:S1109")
            .collect()
    }

    fn expected(line: u32, column: u32) -> Issue {
        Issue {
            rule_key: "csharpsquid:S1109".into(),
            message: "Move this closing curly brace to the next line.".into(),
            range: Range {
                start: Pos { line, column },
                end: Pos {
                    line,
                    column: column + 1,
                },
            },
            fix: None,
            alternatives: Vec::new(),
            flows: Vec::new(),
        }
    }

    #[test]
    fn s1109_exempts_initializer_delimiters_and_retains_multiline_blocks() {
        assert_eq!(findings(CONTROL), vec![expected(18, 22)]);
    }

    #[test]
    fn s1109_keeps_initializers_and_clean_block_braces_unreported() {
        let clean = CONTROL.replace("_ = A.Length; }", "_ = A.Length;\n    }");
        assert!(findings(&clean).is_empty());
    }

    #[test]
    fn s1109_retains_lambda_blocks_nested_in_initializers() {
        assert_eq!(findings(NESTED), vec![expected(7, 22)]);
    }

    #[test]
    fn s1109_preserves_non_ascii_crlf_native_columns() {
        let source = format!("// 😀 café\n{CONTROL}")
            .replace("Cases", "Café")
            .replace("_ = A.Length; }", "_ = \"😀\".Length; }")
            .replace('\n', "\r\n");
        assert_eq!(findings(&source), vec![expected(19, 24)]);
    }

    #[test]
    fn s1109_preserves_ordinary_block_and_inline_exceptions() {
        let source =
            "class C\n{\n    void M()\n    {\n        _ = 1; }\n    void Inline() { _ = 1; }\n}\n";
        assert_eq!(findings(source), vec![expected(5, 15)]);
    }

    #[test]
    fn s1109_does_not_emit_from_unrecoverable_syntax() {
        assert!(findings("class Broken\n{\n int[] X = new[] {\n 1, 2 };\n void M(\n").is_empty());
    }
}
