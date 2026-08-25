// Rule module s5860_tb_named_groups (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// S5860 — named capture groups never referenced by `\k<name>` in the same
/// pattern and not matched through a result object exposing `groups`.
pub(crate) fn check_tb_named_groups(program: &oxc_ast::ast::Program<'_>, sink: &mut IssueSink<'_>) {
    let mut collector = NamedGroupCollector::default();
    collector.visit_program(program);
    for (span, pattern) in &collector.literals {
        for name in defined_group_names(pattern) {
            let exposed = pattern.contains(&format!(r"\k<{name}>"))
                || collector.grouped_literals.contains(span);
            if !exposed {
                sink.emit_span(
                    RuleScope::Both,
                    "S5860",
                    &format!("The named capture group '{name}' is defined but never referenced."),
                    *span,
                );
            }
        }
    }
}

/// `(?<name>…)` definitions inside one pattern; lookbehind `(?<=`/`(?<!`
/// does not define a group.
fn defined_group_names(pattern: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = pattern[cursor..].find("(?<") {
        let begin = cursor + offset + 3;
        let Some(next) = pattern[begin..].chars().next() else {
            break;
        };
        if next == '=' || next == '!' {
            cursor = begin;
            continue;
        }
        match pattern[begin..].find('>') {
            Some(end) => {
                names.push(&pattern[begin..begin + end]);
                cursor = begin + end + 1;
            }
            None => break,
        }
    }
    names
}

#[derive(Default)]
pub(crate) struct NamedGroupCollector {
    pub(crate) literals: Vec<(Span, String)>,
    /// Regex literals passed to `.match`/`.matchAll`/`.exec`, whose result
    /// object exposes `groups`.
    pub(crate) grouped_literals: Vec<Span>,
}
