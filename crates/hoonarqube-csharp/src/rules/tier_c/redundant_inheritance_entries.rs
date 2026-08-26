use super::support::local_type_declarations;
use crate::CsLanguage;
use crate::cst::{base_simple_names, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1939 — inheritance lists repeating an entry or repeating the
/// declared type's own name.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    local_type_declarations(root)
        .into_iter()
        .filter(|declaration| !is_error_tainted(*declaration))
        .filter(|declaration| {
            let bases = base_simple_names(*declaration, source);
            let duplicated =
                (0..bases.len()).any(|index| bases[index + 1..].contains(&bases[index]));
            let self_named = declaration
                .child_by_field_name("name")
                .is_some_and(|name| bases.contains(&node_text(name, source)));
            duplicated || self_named
        })
        .map(|declaration| {
            issue(
                language,
                "S1939",
                "Remove the redundant entry from this inheritance list.",
                range_of(name_anchor(declaration), source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1939_minimal_types_without_base_lists_stay_silent() {
        let report = analyze_default("class Bare\n{\n}\nstruct Solid\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1939").is_empty());
    }

    #[test]
    fn s1939_flags_repeated_simple_name_entry() {
        let report = analyze_default(
            "interface IA\n{\n}\ninterface IB\n{\n}\nclass Dup : IA, IB, IA\n{\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s1939_flags_self_named_record() {
        let report = analyze_default("record Echo : Echo\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s1939_triple_repetition_reports_once() {
        let report = analyze_default("class Trip : IA, IA, IA\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s1939_distinct_and_qualified_bases_stay_clean() {
        let report = analyze_default(
            "class Ok : Exception, IDisposable\n{\n}\nclass Also : System.Exception\n{\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1939").is_empty());
    }

    #[test]
    fn s1939_reports_each_duplicating_type_at_its_own_line() {
        let report = analyze_default("class One : IA, IA\n{\n}\nclass Two : IB, IB\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 4);
    }

    #[test]
    fn s1939_flags_repeated_entry_on_struct() {
        let report = analyze_default("struct Pair : IPair, IPair\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }
}
