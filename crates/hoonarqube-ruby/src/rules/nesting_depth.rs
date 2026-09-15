//! `ruby:S134` — control flow should not be nested too deeply.
//!
//! Contract pinned against the live `SonarQube` 26.8 Community reference
//! (probe-verified on 2026-09-15 against a dedicated scan project, oracle:
//! the pinned `rake` scan): `if`, `unless`, `while`, `until`, `for`,
//! `case`, `begin`, and the modifier forms count as one level each;
//! `elsif`, `else`, `when`, `in`, `rescue`, `ensure`, `case/in` match
//! constructs, ternaries, blocks (`do`/`{}`), lambdas, and `def`/`class`/
//! `module` do not — the rake oracle's depth-1 anchor is a `begin` inside a
//! `do` block inside a method inside a class inside a module. Only the
//! first construct past `max` (catalog default 3) reports; deeper
//! constructs under an already-flagged one stay silent. The finding
//! anchors the construct's keyword and each enclosing counted construct
//! becomes a `Nesting depth N` secondary location, outermost first.

use crate::AnalyzerOptions;
use crate::support::{SourceMap, node_text, walk};
use hoonarqube_ir::{FlowLocation, Issue};
use tree_sitter::Node;

/// Constructs counted as one nesting level each.
const NESTING_KINDS: &[&str] = &[
    "if",
    "unless",
    "while",
    "until",
    "for",
    "case",
    "begin",
    "if_modifier",
    "unless_modifier",
    "while_modifier",
    "until_modifier",
];

/// Keyword token anchoring each counted construct.
fn keyword_of<'a>(node: Node<'a>, source: &'a str) -> Node<'a> {
    let keyword = match node.kind() {
        "if" | "if_modifier" => "if",
        "unless" | "unless_modifier" => "unless",
        "while" | "while_modifier" => "while",
        "until" | "until_modifier" => "until",
        "for" => "for",
        "case" => "case",
        "begin" => "begin",
        _ => node.kind(),
    };
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| !child.is_named() && node_text(*child, source) == keyword)
        .unwrap_or(node)
}

/// Counted ancestors between this construct and the top of the file, in
/// outermost-first order.
fn nesting_chain(node: Node<'_>) -> Vec<Node<'_>> {
    let mut chain = Vec::new();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if NESTING_KINDS.contains(&ancestor.kind()) {
            chain.push(ancestor);
        }
        current = ancestor.parent();
    }
    chain.reverse();
    chain
}

pub(crate) fn check(root: Node<'_>, source: &str, options: &AnalyzerOptions) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }
    let max = options.maximum_nesting_depth;
    let map = SourceMap::new(source);
    let mut issues = Vec::new();
    walk(root, |node| {
        if !node.is_named() || !NESTING_KINDS.contains(&node.kind()) {
            return;
        }
        let chain = nesting_chain(node);
        // Only the first construct past the limit reports: exactly `max`
        // counted ancestors. Deeper constructs under an already-flagged one
        // stay silent, matching the reference.
        if chain.len() != max {
            return;
        }
        let flows: Vec<FlowLocation> = chain
            .iter()
            .enumerate()
            .map(|(index, ancestor)| {
                FlowLocation::in_primary_file(
                    format!("Nesting depth {}", index + 1),
                    map.node_range(keyword_of(*ancestor, source)),
                )
            })
            .collect();
        let mut issue = Issue::new(
            "ruby:S134",
            format!("Refactor this code to not nest more than {max} control flow statements."),
            map.node_range(keyword_of(node, source)),
        );
        if !flows.is_empty() {
            issue = issue.with_flow(flows);
        }
        issues.push(issue);
    });
    issues
}

#[cfg(test)]
mod tests {
    use crate::rules::check_sonar_rules;
    use crate::{AnalyzerOptions, engine::parse_source};

    fn check(source: &str) -> Vec<hoonarqube_ir::Issue> {
        let tree = parse_source(source).expect("probe source parses");
        check_sonar_rules(&tree, source, &AnalyzerOptions::default())
            .into_iter()
            .filter(|issue| issue.rule_key == "ruby:S134")
            .collect()
    }

    #[test]
    fn flags_construct_beyond_max_with_depth_flows() {
        let source = "def f(a, b, c, d)\n  if a\n    if b\n      if c\n        if d\n          x\n        end\n      end\n    end\n  end\nend\n";
        let issues = check(source);
        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(
            issue.message,
            "Refactor this code to not nest more than 3 control flow statements."
        );
        // The fourth `if` keyword: line 5, columns 8..10.
        assert_eq!(issue.range.start.line, 5);
        assert_eq!(issue.range.start.column, 8);
        assert_eq!(issue.range.end.column, 10);
        // One flow per enclosing counted construct, outermost first.
        assert_eq!(issue.flows.len(), 1);
        let locations = &issue.flows[0].locations;
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].message, "Nesting depth 1");
        assert_eq!(locations[0].range.start.line, 2);
        assert_eq!(locations[2].message, "Nesting depth 3");
        assert_eq!(locations[2].range.start.line, 4);
    }

    #[test]
    fn begin_counts_but_blocks_and_methods_do_not() {
        // Mirrors the rake oracle: begin inside a do-block inside a method
        // inside a class is depth 1, so the third nested if is depth 4.
        let source = "class C\n  def f(a, b, c, d)\n    a.each do\n      begin\n        if b\n          if c\n            if d\n              x\n            end\n          end\n        end\n      end\n    end\n  end\nend\n";
        let issues = check(source);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].range.start.line, 7);
        assert_eq!(issues[0].flows[0].locations[0].message, "Nesting depth 1");
        assert_eq!(issues[0].flows[0].locations[0].range.start.line, 4);
    }

    #[test]
    fn deeper_constructs_under_a_flagged_one_stay_silent() {
        // Probe-verified: only the first construct past the limit reports.
        let source = "def f(a, b, c, d, e, f)\n  if a\n    if b\n      if c\n        if d\n          if e\n            if f\n              x\n            end\n          end\n        end\n      end\n    end\n  end\nend\n";
        let issues = check(source);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].range.start.line, 5);
    }
    #[test]
    fn clause_constructs_do_not_count() {
        // Probe-verified: elsif/else, when, rescue, ensure, and case/in
        // match constructs add no level — the if inside them sees only the
        // outer if/case/begin.
        for (source, flagged_line) in [
            // if inside else: else adds no level, so if d is depth 4.
            (
                "def f(a, b, c, d)\n  if a\n    y\n  else\n    if b\n      if c\n        if d\n          x\n        end\n      end\n    end\n  end\nend\n",
                7,
            ),
            // if inside when: case counts, when does not.
            (
                "def f(x, b, c, d)\n  case x\n  when 1\n    if b\n      if c\n        if d\n          x\n        end\n      end\n    end\n  end\nend\n",
                6,
            ),
            // if inside rescue: begin counts, rescue does not.
            (
                "def f(a, b, c, d)\n  begin\n    a\n  rescue\n    if b\n      if c\n        if d\n          x\n        end\n      end\n    end\n  end\nend\n",
                7,
            ),
            // case/in match: neither the match nor its in clauses count,
            // so the innermost if is only depth 3 — silent, not flagged.
            (
                "def f(x, b, c, d)\n  case x\n  in Integer\n    if b\n      if c\n        if d\n          x\n        end\n      end\n    end\n  end\nend\n",
                0,
            ),
        ] {
            let issues = check(source);
            if flagged_line == 0 {
                assert!(issues.is_empty(), "{source}");
            } else {
                assert_eq!(issues.len(), 1, "{source}");
                assert_eq!(issues[0].range.start.line, flagged_line, "{source}");
            }
        }
    }

    #[test]
    fn silent_controls_match_the_reference() {
        for source in [
            // Exactly at the max: allowed.
            "def f(a, b, c)\n  if a\n    if b\n      if c\n        x\n      end\n    end\n  end\nend\n",
            // Blocks do not add depth.
            "def f(a, b, c)\n  a.each do\n    if b\n      if c\n        x\n      end\n    end\n  end\nend\n",
            // Ternaries do not count.
            "def f(a, b, c, d)\n  if a\n    if b\n      if c\n        x = d ? 1 : 2\n      end\n    end\n  end\nend\n",
        ] {
            assert!(check(source).is_empty(), "{source}");
        }
    }
}
