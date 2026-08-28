use crate::cst::{collect_kinds, is_error_tainted, issue, parameters_of, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S107 — methods and constructors take at most the tolerated
/// number of parameters.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["method_declaration", "constructor_declaration"];
    let mut issues = Vec::new();
    for method in collect_kinds(root, &KINDS) {
        if is_error_tainted(method) {
            continue;
        }
        let count = parameters_of(method).len();
        if to_u32(count) > options.maximum_method_parameters {
            let kind = if method.kind() == "constructor_declaration" {
                "Constructor"
            } else {
                "Method"
            };
            let anchor = method.child_by_field_name("parameters").unwrap_or(method);
            issues.push(issue(
                language,
                "S107",
                format!(
                    "{kind} has {count} parameters, which is greater than the {} authorized.",
                    options.maximum_method_parameters
                ),
                range_of(anchor, source),
            ));
        }
    }
    issues
}
