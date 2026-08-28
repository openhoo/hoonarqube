use crate::support::significant_tokens;
use crate::support::to_range;
use hoonarqube_ir::{Issue, TextEdit, apply_fixes};
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S1721 — parentheses right after `assert`, `del`, `return`, `yield`.
/// `print` is deliberately excluded: in Python 3 it is a regular function,
/// so `print(x)` is an ordinary call, not a relic.
///
/// Findings whose non-empty parenthesized region remains valid Python after
/// removal carry a quick fix (`return(1)` → `return 1`); an adjacent opening
/// parenthesis becomes a separating space. Empty regions (`return()`) change
/// meaning, while multiline continuations and generator expressions depend
/// on the parentheses, so those findings stay fix-less.
pub(crate) fn check_keyword_parentheses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const PAREN_KEYWORDS: [&str; 4] = ["assert", "del", "return", "yield"];
    let significant = significant_tokens(parsed);
    let mut issues = Vec::new();
    for (open, pair) in significant.windows(2).enumerate() {
        // ruff lexes these as dedicated keyword tokens, not Name.
        let keyword_kind = matches!(
            pair[0].kind(),
            TokenKind::Name
                | TokenKind::Return
                | TokenKind::Yield
                | TokenKind::Assert
                | TokenKind::Del
        );
        if !(keyword_kind
            && PAREN_KEYWORDS.contains(&&source[pair[0].range()])
            && pair[1].kind() == TokenKind::Lpar
            && pair[1].range().start() == pair[0].range().end())
        {
            continue;
        }
        let keyword = &source[pair[0].range()];
        let close = matching_close(&significant, open + 1);
        let issue_range = close.map_or_else(
            || pair[1].range(),
            |close| {
                ruff_text_size::TextRange::new(
                    pair[1].range().start(),
                    significant[close].range().end(),
                )
            },
        );
        let mut issue = Issue {
            rule_key: "python:S1721".to_string(),
            message: format!("Remove the parentheses after this \"{keyword}\" keyword."),
            range: to_range(issue_range, index, source),
            fix: None,
        };
        // `open` is the keyword's index, so the opening paren sits at
        // `open + 1`; an empty interior (`return()`) would close at
        // `open + 2` and must stay fix-less.
        if let Some(close) = close
            && close > open + 2
        {
            // The rule requires the opening parenthesis to touch the
            // keyword, so replace it with a separator instead of deleting it.
            let edits = vec![
                TextEdit {
                    range: to_range(pair[1].range(), index, source),
                    replacement: " ".to_string(),
                },
                TextEdit {
                    range: to_range(significant[close].range(), index, source),
                    replacement: String::new(),
                },
            ];
            if fix_preserves_syntax(source, &edits) {
                issue = issue.with_fix("Remove redundant parentheses", edits);
            }
        }
        issues.push(issue);
    }
    issues
}

/// Rejects suggestions whose parentheses carry Python grammar, such as a
/// multiline continuation or generator expression. The analyzer parses
/// broken sources tolerantly, so fix eligibility needs this strict check;
/// otherwise re-analysis could mistake a new syntax error for resolution.
fn fix_preserves_syntax(source: &str, edits: &[TextEdit]) -> bool {
    let refs: Vec<&TextEdit> = edits.iter().collect();
    apply_fixes(source, &refs)
        .ok()
        .is_some_and(|fixed| ruff_python_parser::parse_module(&fixed).is_ok())
}

/// Finds the parenthesis matching the open one at `open`, counting nesting
/// over significant tokens; `None` when the parens never balance.
fn matching_close(significant: &[&ruff_python_ast::token::Token], open: usize) -> Option<usize> {
    let mut depth = 1_usize;
    for (offset, token) in significant.iter().enumerate().skip(open + 1) {
        match token.kind() {
            TokenKind::Lpar => depth += 1,
            TokenKind::Rpar => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn return_parentheses_carry_a_working_quick_fix() {
        let report = scan("def f():\n    return(1)\n");
        let issues = findings(&report, "python:S1721");
        assert_eq!(issues.len(), 1);

        let fix = issues[0].fix.as_ref().expect("quick fix attached");
        assert_eq!(fix.message, "Remove redundant parentheses");

        let source = "def f():\n    return(1)\n";
        let refs: Vec<&hoonarqube_ir::TextEdit> = fix.edits.iter().collect();
        let fixed = hoonarqube_ir::apply_fixes(source, &refs).expect("applies cleanly");
        assert_eq!(fixed, "def f():\n    return 1\n");
    }

    #[test]
    fn adjacent_parens_get_fixes_but_empty_region_does_not() {
        let source = "def f(flag):\n    x = flag\n    del(x)\n    return()\n";
        let report = scan(source);
        let issues = findings(&report, "python:S1721");
        // The rule requires a paren glued to the keyword: `del(x)` and the
        // empty `return()` fire, spaced or non-adjacent forms do not.
        assert_eq!(issues.len(), 2);

        let del_issue = issues
            .iter()
            .find(|issue| issue.message.contains("\"del\""))
            .expect("del finding");
        let fix = del_issue.fix.as_ref().expect("del fix");
        let refs: Vec<&hoonarqube_ir::TextEdit> = fix.edits.iter().collect();
        let fixed = hoonarqube_ir::apply_fixes(source, &refs).expect("applies cleanly");
        assert!(fixed.contains("del x\n"));

        // Unparenthesizing an empty tuple changes semantics: stay fix-less.
        let empty_tuple = issues
            .iter()
            .find(|issue| issue.message.contains("\"return\""))
            .expect("return finding");
        assert!(empty_tuple.fix.is_none(), "return() must stay fix-less");
    }

    #[test]
    fn syntax_dependent_parentheses_stay_fixless() {
        for source in [
            "def f():\n    return(\n        1\n    )\n",
            "def f(xs):\n    return(x for x in xs)\n",
        ] {
            let report = scan(source);
            let issues = findings(&report, "python:S1721");
            assert_eq!(issues.len(), 1);
            assert!(
                issues[0].fix.is_none(),
                "removing grammar-bearing parentheses must not be suggested"
            );
        }
    }
}
