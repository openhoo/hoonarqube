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
        // Loop-invariant: whether this literal is consumed through a result
        // object exposing `groups` (checked once, not per group name).
        let via_consuming_call = collector.grouped_literals.contains(span);
        for name in defined_group_names(pattern) {
            let exposed = pattern.contains(&format!(r"\k<{name}>")) || via_consuming_call;
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
    /// Regex literals consumed as a `.exec` receiver or passed to
    /// `.match`/`.matchAll`, whose result object exposes `groups`.
    pub(crate) grouped_literals: Vec<Span>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn consuming_calls_expose_named_groups() {
        // `.exec` receiver: result exposes `groups`.
        let direct_exec = js_keys("const m = /(?<x>a)b/.exec(s);\n");
        assert_eq!(count_key(&direct_exec, "javascript:S5860"), 0);

        // `String.prototype.match` / `.matchAll` argument: same exposure.
        let string_match = js_keys("const m = s.match(/(?<x>a)/);\n");
        assert_eq!(count_key(&string_match, "javascript:S5860"), 0);
        let string_match_all = js_keys("for (const m of s.matchAll(/(?<x>a)/g)) {}\n");
        assert_eq!(count_key(&string_match_all, "javascript:S5860"), 0);
    }

    #[test]
    fn exec_on_unrelated_object_still_flags_the_regex_argument() {
        // `foo.exec(...)` is not `RegExp.prototype.exec`; its argument gets
        // no exemption.
        let foreign_exec = js_keys("const m = foo.exec(/(?<x>a)/);\n");
        assert_eq!(count_key(&foreign_exec, "javascript:S5860"), 1);
    }
}
