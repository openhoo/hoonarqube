use crate::support::to_u32;
use oxc_ast::ast::{Expression, RegExpFlags, RegExpLiteral};
use oxc_span::{GetSpan, Span};

mod matcher;
mod parser;
mod site;
mod tree;

pub(crate) use matcher::*;
pub(crate) use parser::*;
pub(crate) use site::*;
pub(crate) use tree::*;

/// Group-nesting cap shared by both regex parsers (`PatternParser` for
/// pattern trees, `RegexParser` for catalog patterns), mirroring the Python
/// crate's `RX_MAX_DEPTH`: beyond this depth parsing bails out instead of
/// risking stack exhaustion on runaway nesting such as tens of thousands
/// of `(` levels inside one literal.
pub(crate) const MAX_GROUP_DEPTH: u32 = 48;

#[cfg(test)]
mod tests {
    use super::*;

    /// Unterminated character classes are definite syntax errors for the
    /// pattern-tree parser and compile to nothing for the tolerant catalog
    /// matcher — either way the scan must terminate instead of hanging or
    /// panicking on the missing `]`.
    #[test]
    fn unterminated_character_class_terminates_as_error() {
        for pattern in ["[", "[^", "[a-", "[\\", "ab[", "[a-\\"] {
            assert!(
                parse_regex_pattern(pattern, false).is_err(),
                "`{pattern}` should be a definite syntax error",
            );
            assert!(
                parse_regex_pattern(pattern, true).is_err(),
                "`{pattern}` in unicode mode should be a definite syntax error",
            );
            assert!(
                parse_regex(pattern).is_none(),
                "`{pattern}` should not compile"
            );
            assert!(
                !regex_search(pattern, "needle"),
                "`{pattern}` should match nothing"
            );
        }
    }

    #[test]
    fn terminated_classes_still_parse_and_match() {
        assert!(parse_regex_pattern("[abc]", false).is_ok());
        assert!(parse_regex_pattern("[^abc]", false).is_ok());
        // Annex B: a trailing dash stays literal even next to a shorthand.
        assert!(parse_regex_pattern("[\\d-a]", false).is_ok());
        assert!(regex_search("[abc]", "b"));
        assert!(!regex_search("[abc]", "x"));
        // A leading `]` is a literal class member, not a terminator.
        assert!(regex_search("[]]", "]"));
    }

    #[test]
    fn runaway_group_nesting_bails_out_without_crashing() {
        // ~10k nested groups: far past the depth cap for both parsers, and
        // exactly the shape that previously recursed without any bound.
        let deep = format!("^(?:{}x{})$", "(?:".repeat(10_000), ")".repeat(10_000));
        assert!(parse_regex_pattern(&deep, false).is_err());
        assert!(parse_regex_pattern(&deep, true).is_err());
        assert!(parse_regex(&deep).is_none());
        assert!(!regex_search(&deep, "x"));

        // Nesting just under the cap still parses normally.
        let under = (MAX_GROUP_DEPTH - 1) as usize;
        let shallow = format!("^{}x{}$", "(?:".repeat(under), ")".repeat(under));
        assert!(parse_regex_pattern(&shallow, false).is_ok());
        assert!(regex_search(&shallow, "x"));
    }

    #[test]
    fn nested_node_spans_end_at_their_own_delimiters() {
        let parsed = parse_regex_pattern("x(a|b)y[cd]z", false).expect("valid regex");
        let mut spans = Vec::new();
        for alternative in &parsed.alternatives {
            walk_pattern_nodes(alternative, &mut |node| match node {
                PatternNode::Group { start, end, .. } => spans.push(("group", *start, *end)),
                PatternNode::Class { start, end, .. } => spans.push(("class", *start, *end)),
                _ => {}
            });
        }
        assert_eq!(spans, vec![("group", 1, 6), ("class", 7, 11)]);
    }

    #[test]
    fn catalog_matcher_handles_long_repetitions_and_documented_escapes() {
        assert!(regex_search(r"^\w$", "_"));
        assert!(regex_prefix_match(r"^\t$", "\t"));
        assert!(regex_prefix_match(r"^\n$", "\n"));
        assert!(regex_search("^a*$", &"a".repeat(100_000)));
        assert!(!regex_search(&"a".repeat(10_000), "short"));
    }

    #[test]
    fn catalog_matcher_rejects_reversed_ranges_and_keeps_shorthand_dashes_literal() {
        assert!(parse_regex("[z-a]").is_none());
        assert!(regex_search(r"[\d-a]", "-"));
        assert!(regex_search(r"[\d-a]", "8"));
        assert!(regex_search(r"[\d-a]", "a"));
    }
}
