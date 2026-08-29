use crate::CsLanguage;
use crate::cst::{issue, node_text, parameters_of, range_of};
use crate::rules::linq_api::methods_grouped_by_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3427 — overlapping defaults make some call sites ambiguous.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let shapes: Vec<ParameterShape> = methods
            .iter()
            .map(|method| parameter_shape(*method, source))
            .collect();
        for first in 0..methods.len() {
            for second in (first + 1)..methods.len() {
                if shapes[first].overlaps(&shapes[second]) {
                    let first_line = methods[first].start_position().row + 1;
                    let anchor = parameters_of(methods[second])
                        .into_iter()
                        .find(|parameter| has_default(*parameter))
                        .unwrap_or(methods[second]);
                    issues.push(issue(
                        language,
                        "S3427",
                        format!(
                            "This method signature overlaps the one defined on line {first_line}, the default parameter value can't be used."
                        ),
                        range_of(anchor, source),
                    ));
                }
            }
        }
    }
    issues
}

struct ParameterShape {
    required: usize,
    signatures: Vec<String>,
}

impl ParameterShape {
    fn overlaps(&self, other: &Self) -> bool {
        let upper = self.signatures.len().min(other.signatures.len());
        let lower = self.required.max(other.required);
        let has_default =
            self.required < self.signatures.len() || other.required < other.signatures.len();
        has_default
            && (lower..=upper).any(|arity| self.signatures[..arity] == other.signatures[..arity])
    }
}

/// Mandatory count and normalized parameter signatures of a method.
fn parameter_shape(method: Node<'_>, source: &str) -> ParameterShape {
    let parameters = parameters_of(method);
    ParameterShape {
        required: parameters
            .iter()
            .filter(|parameter| !has_default(**parameter))
            .count(),
        signatures: parameters
            .into_iter()
            .map(|parameter| parameter_signature(parameter, source))
            .collect(),
    }
}

fn has_default(parameter: Node<'_>) -> bool {
    let mut cursor = parameter.walk();
    parameter
        .children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == "=")
}

fn parameter_signature(parameter: Node<'_>, source: &str) -> String {
    let mut signature = String::new();
    let mut cursor = parameter.walk();
    for modifier in parameter
        .children(&mut cursor)
        .filter(|child| child.kind() == "modifier")
        .map(|modifier| node_text(modifier, source))
        .filter(|modifier| matches!(*modifier, "in" | "out" | "ref"))
    {
        signature.push_str(modifier);
        signature.push(' ');
    }
    if let Some(type_node) = parameter.child_by_field_name("type") {
        signature.extend(
            node_text(type_node, source)
                .chars()
                .filter(|character| !character.is_whitespace()),
        );
    }
    signature
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3427_allows_identical_signatures_without_defaults() {
        let report = analyze_default(
            "class A\n{\n    public int Sum(int a) { return a; }\n    public int Sum(int b) { return b; }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3427").is_empty());
    }

    #[test]
    fn s3427_groups_overloads_per_enclosing_type() {
        let report = analyze_default(
            "class A\n{\n    public void Send(int a) { }\n}\n\nclass B\n{\n    public void Send(int a, int b = 1) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3427").is_empty());
    }

    #[test]
    fn s3427_flags_exactly_touching_mandatory_ranges() {
        let report = analyze_default(
            "class A\n{\n    public void Save(int a, int b) { }\n    public void Save(int a, int b, int c = 3) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3427");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s3427_counts_each_ambiguous_pair_separately() {
        let report = analyze_default(
            "class A\n{\n    public void Run(int a) { }\n    public void Run(int a, int b = 1) { }\n    public void Run(int a, int b = 2, int c = 3) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3427");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 4);
        assert_eq!(flagged[1].range.start.line, 5);
        assert_eq!(flagged[2].range.start.line, 5);
    }

    #[test]
    fn s3427_requires_compatible_parameter_prefixes() {
        let report = analyze_default(
            "class A\n{\n    public void Send(int value) { }\n    public void Send(string value, int retries = 1) { }\n    public void Read(ref int value) { }\n    public void Read(int value, int retries = 1) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3427").is_empty());
    }

    #[test]
    fn s3427_ignores_attributes_when_detecting_defaults() {
        let report = analyze_default(
            "class A\n{\n    public void Send([A] int value) { }\n    public void Send(int value, int retries = 1) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3427");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }
}
