use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::{creation_type_text, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4347 — secure generation made predictable through constant
/// seeding. Honest subset: `Random`-typed creations with exactly one integer
/// literal seed argument.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| simple_name(creation_type_text(*creation, source)).ends_with("Random"))
        .filter(|creation| {
            let arguments = invocation_arguments(*creation);
            arguments.len() == 1 && argument_expression(arguments[0]).kind() == "integer_literal"
        })
        .map(|creation| {
            issue(
                language,
                "S4347",
                "Seed this generator unpredictably; a constant seed produces predictable values.",
                range_of(creation),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4347_ignores_sources_without_generators() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S4347").is_empty());
    }

    #[test]
    fn s4347_ignores_runtime_seeds() {
        let report =
            analyze_default("int seed = Environment.TickCount;\nvar rng = new Random(seed);\n");
        assert!(with_key(&report, "csharpsquid:S4347").is_empty());
    }

    #[test]
    fn s4347_ignores_wrong_argument_counts_and_kinds() {
        let report = analyze_default("var a = new Random(1, 2);\nvar b = new Random(-42);\n");
        assert!(with_key(&report, "csharpsquid:S4347").is_empty());
    }

    #[test]
    fn s4347_flags_random_suffix_type_names() {
        let report = analyze_default("var rng = new SecureRandom(42);\n");
        let found = with_key(&report, "csharpsquid:S4347");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
    }

    #[test]
    fn s4347_flags_qualified_generator_types() {
        let report = analyze_default("var rng = new System.Random(7);\n");
        let found = with_key(&report, "csharpsquid:S4347");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
    }

    #[test]
    fn s4347_flags_each_seeded_generator_at_its_own_line() {
        let report = analyze_default("var first = new Random(1);\nvar second = new Random(2);\n");
        let found = with_key(&report, "csharpsquid:S4347");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 1);
        assert_eq!(found[1].range.start.line, 2);
    }
}
