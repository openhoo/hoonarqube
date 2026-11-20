use crate::CsLanguage;
use crate::cst::{ancestors_of, issue, range_from_byte_offsets, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S122 — statements, including embedded bodies, live on separate
/// lines. Anonymous functions have their own statement counts; their containing
/// statement still contributes to the full displayed range on that line.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut statements_per_row: std::collections::BTreeMap<usize, Vec<Node>> =
        std::collections::BTreeMap::new();
    walk_all(root, &mut |node| {
        if node.kind() != "global_statement" && node.kind().ends_with("_statement") {
            statements_per_row
                .entry(node.start_position().row)
                .or_default()
                .push(node);
        }
    });
    let mut issues = Vec::new();
    for row_statements in statements_per_row.values() {
        let mut scopes = std::collections::BTreeSet::new();
        let repeated_scope = row_statements.iter().any(|statement| {
            let scope = ancestors_of(*statement)
                .find(|ancestor| {
                    matches!(
                        ancestor.kind(),
                        "lambda_expression" | "anonymous_method_expression"
                    )
                })
                .map(|ancestor| ancestor.id());
            !scopes.insert(scope)
        });
        if let Some(first) = row_statements.first()
            && repeated_scope
        {
            // Preorder's last child may end before its containing statement's
            // closing brace, semicolon, or later-line body.
            let end = row_statements
                .iter()
                .map(Node::end_byte)
                .max()
                .unwrap_or(first.end_byte());
            issues.push(issue(
                language,
                "S122",
                "Reformat the code to have only one statement per line.",
                range_from_byte_offsets(first.start_byte(), end, source),
            ));
        }
    }
    issues
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};
    use serde_json::{Value, json};

    // Executed installed SonarAnalyzer.CSharp 10.33 witnesses: 30 syntax and
    // seven anonymous-function cases, each in LF and Unicode/CRLF form.
    const SYNTAX: &str = r"using System;
namespace Scope;
class Cases
{
    void Step() { }
    void if_inline(bool b)
    {
        if (b) Step();
    }
    void if_return(bool b)
    {
        if (b) return;
    }
    void if_multiline(bool b)
    {
        if (b)
            Step();
    }
    void if_inline_block(bool b)
    {
        if (b) { Step(); }
    }
    void if_empty_block(bool b)
    {
        if (b) { }
    }
    void if_else_inline(bool b)
    {
        if (b) Step(); else Step();
    }
    void if_else_multiline(bool b)
    {
        if (b)
            Step();
        else
            Step();
    }
    void else_inline(bool b)
    {
        if (b)
            Step();
        else Step();
    }
    void nested_if_inline(bool b)
    {
        if (b) if (b) Step();
    }
    void if_multiline_condition(bool b)
    {
        if (
            b) Step();
    }
    void if_trailing_sibling(bool b)
    {
        if (b) Step(); Step();
    }
    void if_block_sibling(bool b)
    {
        if (b) { } Step();
    }
    void two_siblings(bool b)
    {
        Step(); Step();
    }
    void one_statement(bool b)
    {
        Step();
    }
    void while_inline(bool b)
    {
        while (b) Step();
    }
    void while_multiline(bool b)
    {
        while (b)
            Step();
    }
    void for_inline(bool b)
    {
        for (int i = 0; i < 1; i++) Step();
    }
    void for_empty_block(bool b)
    {
        for (int i = 0; i < 1; i++) { }
    }
    void foreach_inline(bool b)
    {
        foreach (var x in new[] { 1 }) Step();
    }
    void do_inline(bool b)
    {
        do Step(); while (b);
    }
    void do_multiline(bool b)
    {
        do
            Step();
        while (b);
    }
    void lock_inline(bool b)
    {
        lock (this) Step();
    }
    void using_inline(bool b)
    {
        using (var s = new System.IO.MemoryStream()) Step();
    }
    void checked_inline(bool b)
    {
        checked { Step(); }
    }
    void unchecked_inline(bool b)
    {
        unchecked { Step(); }
    }
    void try_catch_inline(bool b)
    {
        try { Step(); } catch (Exception) { Step(); }
    }
    void local_function_inline(bool b)
    {
        void Local() { Step(); }
    }
    void lambda_inline(bool b)
    {
        Action f = () => { Step(); };
    }
    void unicode_if(bool b)
    {
        /* 😀 café */ if (b) Step();
    }
    void empty_statement_inline(bool b)
    {
        if (b) ;
    }
}
";

    const CALLABLES: &str = r"using System;
namespace Scope;
class Callables
{
    void Step() { }
    void lambda_one(bool b)
    {
        Action f = () => { Step(); };
    }
    void lambda_two(bool b)
    {
        Action f = () => { Step(); Step(); };
    }
    void lambda_if(bool b)
    {
        Action f = () => { if (b) Step(); };
    }
    void anonymous_one(bool b)
    {
        Action f = delegate { Step(); };
    }
    void anonymous_two(bool b)
    {
        Action f = delegate { Step(); Step(); };
    }
    void lambda_outer_sibling(bool b)
    {
        Action f = () => { Step(); }; Step();
    }
    void lambda_multiline_two(bool b)
    {
        Action f = () =>
        {
            Step(); Step();
        };
    }
}
";

    const ORIGINAL: &str = r#"using System;
class Cases
{
    string M(int number)
    {
        if (number == 11) return "ενδέκατος";
        return string.Empty;
    }
}
"#;

    const BAD: &str = r"class Pipeline
{
    void Run()
    {
        Load();
        Save(); Archive();
        Purge();
    }
}
";

    const GOOD: &str = r"class Pipeline
{
    void Run()
    {
        Load();
        Save();
        Archive();
        Purge();
    }
}
";

    fn unicode(source: &str) -> String {
        format!("// 😀 café\n{source}").replace('\n', "\r\n")
    }

    fn check(source: &str, rows: &[(u32, u32, u32, u32)]) {
        let report = analyze_default(source);
        let actual: Vec<Value> = with_key(&report, "csharpsquid:S122")
            .into_iter()
            .map(|i| serde_json::to_value(i).unwrap())
            .collect();
        let expected: Vec<Value> = rows.iter().map(|&(sl, sc, el, ec)| {
            json!({"rule_key":"csharpsquid:S122","message":"Reformat the code to have only one statement per line.","range":{"start":{"line":sl,"column":sc},"end":{"line":el,"column":ec}}})
        }).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn s122_installed_lf() {
        check(
            SYNTAX,
            &[
                (8, 8, 8, 22),
                (12, 8, 12, 22),
                (21, 8, 21, 26),
                (29, 8, 29, 35),
                (46, 8, 46, 29),
                (55, 8, 55, 30),
                (59, 8, 59, 26),
                (63, 8, 63, 23),
                (71, 8, 71, 25),
                (80, 8, 80, 43),
                (88, 8, 88, 46),
                (92, 8, 92, 29),
                (102, 8, 102, 27),
                (106, 8, 106, 60),
                (110, 8, 110, 27),
                (114, 8, 114, 29),
                (118, 8, 118, 53),
                (122, 8, 122, 32),
                (130, 21, 130, 35),
                (134, 8, 134, 16),
            ],
        );
    }

    #[test]
    fn s122_installed_unicode_crlf() {
        check(
            &unicode(SYNTAX),
            &[
                (9, 8, 9, 22),
                (13, 8, 13, 22),
                (22, 8, 22, 26),
                (30, 8, 30, 35),
                (47, 8, 47, 29),
                (56, 8, 56, 30),
                (60, 8, 60, 26),
                (64, 8, 64, 23),
                (72, 8, 72, 25),
                (81, 8, 81, 43),
                (89, 8, 89, 46),
                (93, 8, 93, 29),
                (103, 8, 103, 27),
                (107, 8, 107, 60),
                (111, 8, 111, 27),
                (115, 8, 115, 29),
                (119, 8, 119, 53),
                (123, 8, 123, 32),
                (131, 21, 131, 35),
                (135, 8, 135, 16),
            ],
        );
    }

    #[test]
    fn s122_installed_callables() {
        check(
            CALLABLES,
            &[
                (12, 8, 12, 45),
                (16, 8, 16, 44),
                (24, 8, 24, 48),
                (28, 8, 28, 45),
                (34, 12, 34, 27),
            ],
        );
    }

    #[test]
    fn s122_installed_callables_unicode_crlf() {
        check(
            &unicode(CALLABLES),
            &[
                (13, 8, 13, 45),
                (17, 8, 17, 44),
                (25, 8, 25, 48),
                (29, 8, 29, 45),
                (35, 12, 35, 27),
            ],
        );
    }

    #[test]
    fn s122_installed_original_minimized() {
        check(ORIGINAL, &[(6, 8, 6, 45)]);
    }

    #[test]
    fn s122_installed_original_bad() {
        check(BAD, &[(6, 8, 6, 26)]);
    }

    #[test]
    fn s122_installed_original_good() {
        check(GOOD, &[]);
    }

    #[test]
    fn s122_malformed_source_preserves_incomplete_analysis() {
        let source = "class Broken { void M( if (b) Step(); }\n";
        assert!(crate::parse(source).root_node().has_error());
        check(source, &[]);
    }
}
