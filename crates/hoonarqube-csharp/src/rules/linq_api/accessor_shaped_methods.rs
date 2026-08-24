use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::security::return_type_text;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4049 — `Get`/`Set` pairs read as properties.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let spelled = node_text(name, source);
        let returns_void = simple_name(return_type_text(method, source)) == "void";
        let parameters = parameters_of(method).len();
        if spelled.len() > 3
            && spelled.starts_with('G')
            && spelled[1..].starts_with("et")
            && spelled
                .chars()
                .nth(3)
                .is_some_and(|c: char| c.is_ascii_uppercase())
            && parameters == 0
            && !returns_void
        {
            issues.push(issue(
                language,
                "S4049",
                "Convert this getter method into a property.",
                range_of(name_anchor(method)),
            ));
        } else if spelled.len() > 3
            && spelled.starts_with("Set")
            && spelled
                .chars()
                .nth(3)
                .is_some_and(|c: char| c.is_ascii_uppercase())
            && parameters == 1
        {
            issues.push(issue(
                language,
                "S4049",
                "Convert this setter method into a property.",
                range_of(name_anchor(method)),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4049_enforces_prefix_case_and_shape_boundaries() {
        let report = analyze_default(
            "class F\n{\n    public string Get() { return name; }\n    public string Gets() { return name; }\n    public void SetName() { }\n    public void Setname(string newValue) { }\n    public void GetName() { }\n    public string GetName(int id) { return name; }\n    public void SetValue(string newValue) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4049");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9); // document line 8
    }

    #[test]
    fn s4049_minimal_class_without_methods_is_clean() {
        let report = analyze_default("class F\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S4049").is_empty());
    }
}
