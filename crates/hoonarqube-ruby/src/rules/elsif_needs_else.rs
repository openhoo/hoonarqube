//! `ruby:S126` — `if`/`elsif` chains should end with an `else`.
//!
//! Contract pinned against the live `SonarQube` 26.8 Community reference
//! (probe-verified on 2026-09-15, oracle: the pinned `rake` scan): a plain
//! `if` without `else` is fine; once a chain has an `elsif`, the reference
//! expects a terminal `else` and reports the *last* `elsif` keyword when it
//! is missing — unless every branch ends in a jump (`return`, `break`,
//! `next`, or a `raise` call), in which case the chain is exempt. `case`/
//! `when` without `else` is a different rule (`ruby:S131`) and stays silent
//! here, as do modifier forms (`x if y`), which cannot take an `elsif`.

use crate::support::{SourceMap, node_text, walk};
use hoonarqube_ir::{Issue, Range};
use tree_sitter::Node;

pub(crate) fn check(root: Node<'_>, source: &str) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }
    let map = SourceMap::new(source);
    let mut issues = Vec::new();
    walk(root, |node| {
        if !node.is_named() || !matches!(node.kind(), "if" | "unless") {
            return;
        }
        if let Some(tail) = missing_else_tail(node, source) {
            issues.push(Issue::new(
                "ruby:S126",
                "Add the missing \"else\" clause.",
                keyword_range(&map, tail, source),
            ));
        }
    });
    issues
}

/// Walks the `alternative` chain (`elsif` → `elsif` → `else`). Returns the
/// last `elsif` node when the chain has at least one `elsif`, no terminal
/// `else`, and at least one branch that does not end in a jump; `None` for
/// a plain `if`, a chain that already ends in `else`, or an all-jump chain.
fn missing_else_tail<'a>(head: Node<'a>, source: &'a str) -> Option<Node<'a>> {
    let mut current = head;
    let mut saw_elsif = false;
    let mut all_jumped = branch_jumps(head, source);
    loop {
        match current.child_by_field_name("alternative") {
            Some(alternative) if alternative.kind() == "elsif" => {
                saw_elsif = true;
                all_jumped &= branch_jumps(alternative, source);
                current = alternative;
            }
            // An `else` (or anything else) terminates the chain cleanly.
            Some(_) => return None,
            None => {
                return (saw_elsif && !all_jumped).then_some(current);
            }
        }
    }
}

/// Whether this `if`/`elsif` clause's consequence ends in a jump. The
/// reference exempts chains whose every branch jumps.
fn branch_jumps(clause: Node<'_>, source: &str) -> bool {
    let Some(consequence) = clause.child_by_field_name("consequence") else {
        return false;
    };
    let mut cursor = consequence.walk();
    let last = consequence.named_children(&mut cursor).last();
    last.is_some_and(|statement| is_jump(statement, source))
}

/// `return`, `break`, `next`, and `raise` calls end a branch. `redo`,
/// `retry`, `fail`, `throw`, and `exit` do not (probe-verified).
fn is_jump(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "return" | "break" | "next" => true,
        "call" => {
            node.child_by_field_name("receiver").is_none()
                && node
                    .child_by_field_name("method")
                    .is_some_and(|method| node_text(method, source) == "raise")
        }
        // A bare `raise` parses as an identifier.
        "identifier" => node_text(node, source) == "raise",
        _ => false,
    }
}

/// The `elsif` keyword's own span — the reference anchors the finding on the
/// keyword, not the whole clause.
fn keyword_range(map: &SourceMap, node: Node<'_>, source: &str) -> Range {
    let mut cursor = node.walk();
    let keyword = node
        .children(&mut cursor)
        .find(|child| !child.is_named() && node_text(*child, source) == "elsif")
        .unwrap_or(node);
    map.node_range(keyword)
}

#[cfg(test)]
mod tests {
    use crate::rules::check_sonar_rules;
    use crate::{AnalyzerOptions, engine::parse_source};

    fn check(source: &str) -> Vec<hoonarqube_ir::Issue> {
        let tree = parse_source(source).expect("probe source parses");
        check_sonar_rules(&tree, source, &AnalyzerOptions::default())
            .into_iter()
            .filter(|issue| issue.rule_key == "ruby:S126")
            .collect()
    }

    #[test]
    fn flags_last_elsif_keyword_when_else_is_missing() {
        let issues = check(
            "def f(a, b, c)\n  if a\n    x\n  elsif b\n    y\n  elsif c\n    z\n  end\nend\n",
        );
        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.message, "Add the missing \"else\" clause.");
        // The last `elsif` keyword: line 6, columns 2..7.
        assert_eq!(issue.range.start.line, 6);
    }

    #[test]
    fn all_jump_chains_are_exempt() {
        // Probe-verified: every branch ending in a jump excuses the else.
        for source in [
            // return in both branches — the rake oracle's silent site.
            "def f(a, b)\n  if a\n    return x\n  elsif b\n    return y\n  end\nend\n",
            // raise counts as a jump.
            "def f(a, b)\n  if a\n    raise \"x\"\n  elsif b\n    raise \"y\"\n  end\nend\n",
            // break/next count inside a block.
            "def f(a, b)\n  [1].each do\n    if a\n      break\n    elsif b\n      next\n    end\n  end\nend\n",
        ] {
            assert!(check(source).is_empty(), "{source}");
        }
    }

    #[test]
    fn partial_jump_chains_still_report() {
        // Probe-verified: one non-jumping branch keeps the finding.
        for (source, line) in [
            (
                "def f(a, b)\n  if a\n    x\n  elsif b\n    return y\n  end\nend\n",
                4,
            ),
            (
                "def f(a, b)\n  if a\n    return x\n  elsif b\n    y\n  end\nend\n",
                4,
            ),
            // fail/throw/exit are not jumps.
            (
                "def f(a, b)\n  if a\n    fail \"x\"\n  elsif b\n    fail \"y\"\n  end\nend\n",
                4,
            ),
            (
                "def f(a, b)\n  if a\n    throw :x\n  elsif b\n    throw :y\n  end\nend\n",
                4,
            ),
            // redo/retry are not jumps.
            (
                "def f(a, b)\n  [1].each do\n    if a\n      redo\n    elsif b\n      retry\n    end\n  end\nend\n",
                5,
            ),
            // An empty branch is not a jump.
            (
                "def f(a, b)\n  if a\n  elsif b\n    return y\n  end\nend\n",
                3,
            ),
        ] {
            let issues = check(source);
            assert_eq!(issues.len(), 1, "{source}");
            assert_eq!(issues[0].range.start.line, line, "{source}");
        }
    }

    #[test]
    fn silent_controls_match_the_reference() {
        for source in [
            // Plain if without else: allowed.
            "def f(a)\n  if a\n    x\n  end\nend\n",
            // if/elsif/else: complete chain.
            "def f(a, b)\n  if a\n    x\n  elsif b\n    y\n  else\n    z\n  end\nend\n",
            // case/when without else is S131's job, not S126's.
            "def f(x)\n  case x\n  when 1\n    y\n  end\nend\n",
            // Modifier if cannot take an elsif.
            "def f(a)\n  x if a\nend\n",
        ] {
            assert!(check(source).is_empty(), "{source}");
        }
    }
}
