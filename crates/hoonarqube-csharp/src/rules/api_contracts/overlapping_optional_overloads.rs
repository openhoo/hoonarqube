use crate::CsLanguage;
use crate::cst::{issue, parameters_of, range_of};
use crate::rules::linq_api::methods_grouped_by_name;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3427 — overlapping defaults make some call sites ambiguous.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let shapes: Vec<(usize, usize)> = methods
            .iter()
            .map(|method| parameter_shape(*method))
            .collect();
        for first in 0..methods.len() {
            for second in (first + 1)..methods.len() {
                let (params_first, optional_first) = shapes[first];
                let (params_second, optional_second) = shapes[second];
                let lower = params_first
                    .saturating_sub(optional_first)
                    .max(params_second.saturating_sub(optional_second));
                let upper = params_first.min(params_second);
                let ambiguous = lower <= upper
                    && (params_first != params_second || optional_first > 0 || optional_second > 0);
                if ambiguous {
                    issues.push(issue(
                        language,
                        "S3427",
                        "Remove the ambiguity between these overloads.",
                        range_of(name_anchor(methods[second])),
                    ));
                }
            }
        }
    }
    issues
}

/// Mandatory and optional parameter counts of a method.
fn parameter_shape(method: Node<'_>) -> (usize, usize) {
    let parameters = parameters_of(method);
    let optional = parameters.iter().filter(|parameter| {
        let mut cursor = parameter.walk();
        parameter.named_children(&mut cursor).count() > 2
    });
    (parameters.len(), optional.count())
}
