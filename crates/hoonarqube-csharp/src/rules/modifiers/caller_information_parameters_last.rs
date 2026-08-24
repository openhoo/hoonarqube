use super::support::has_attribute;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, modifiers_of, parameters_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3343 — caller-information parameters must trail everything
/// but a `params` array.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const CALLER_ATTRIBUTES: [&str; 3] = ["CallerMemberName", "CallerLineNumber", "CallerFilePath"];
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration", "constructor_declaration"]) {
        let parameters = parameters_of(method);
        for (index, parameter) in parameters.iter().enumerate() {
            let attributes = attributes_of(*parameter, source);
            if !CALLER_ATTRIBUTES
                .iter()
                .any(|wanted| has_attribute(&attributes, wanted))
            {
                continue;
            }
            let blocked = parameters[index + 1..]
                .iter()
                .any(|later| !has_modifier(&modifiers_of(*later, source), "params"));
            if blocked {
                issues.push(issue(
                    language,
                    "S3343",
                    "Move this caller-information parameter to the end of the parameter list.",
                    range_of(*parameter),
                ));
            }
        }
    }
    issues
}
