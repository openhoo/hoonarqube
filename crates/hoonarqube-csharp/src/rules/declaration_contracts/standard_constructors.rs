use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, range_of,
};
use crate::rules::expressions::constructor_arities;
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4027 — exception types provide `( )`, `(string)`, and
/// `(string, Exception)` constructors so callers can wrap uniformly.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const STANDARD_ARITIES: [usize; 3] = [0, 1, 2];
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        let derives_exception = base_simple_names(class_declaration, source)
            .iter()
            .any(|base| base.ends_with("Exception"));
        let modifiers = modifiers_of(class_declaration, source);
        if !derives_exception
            || has_modifier(&modifiers, "abstract")
            || has_modifier(&modifiers, "static")
        {
            continue;
        }
        let arities = constructor_arities(class_declaration);
        let complete = STANDARD_ARITIES.iter().all(|arity| arities.contains(arity));
        if !complete {
            issues.push(issue(
                language,
                "S4027",
                "Provide the standard exception constructors.",
                range_of(name_anchor(class_declaration), source),
            ));
        }
    }
    issues
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4027_flags_partial_standard_sets() {
        let message_only = analyze_default(
            "class BoomError : System.Exception\n{\n    public BoomError(string message) { }\n}\n",
        );
        assert_eq!(with_key(&message_only, "csharpsquid:S4027").len(), 1);

        let missing_pair = analyze_default(
            "class BoomError : System.Exception\n{\n    public BoomError() { }\n\n    public BoomError(string message) { }\n}\n",
        );
        assert_eq!(with_key(&missing_pair, "csharpsquid:S4027").len(), 1);
    }

    #[test]
    fn s4027_exempts_abstract_and_non_exception_types() {
        let abstract_form = analyze_default(
            "abstract class BoomError : System.Exception\n{\n    protected BoomError() { }\n}\n",
        );
        assert!(with_key(&abstract_form, "csharpsquid:S4027").is_empty());

        let plain = analyze_default("class Plain\n{\n    public Plain() { }\n}\n");
        assert!(with_key(&plain, "csharpsquid:S4027").is_empty());
    }

    #[test]
    fn s4027_checks_custom_exception_bases_by_name() {
        let report = analyze_default("class DbError : DataException\n{\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S4027").len(), 1);
    }
}
