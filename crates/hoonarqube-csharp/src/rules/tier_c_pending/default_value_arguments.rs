use super::support::invocation_is_positional;
use super::support::local_method_table;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use crate::rules::tier_c::parameter_units;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3254 — explicit arguments duplicating the callee's parameter
/// default. Subset: fully positional calls against file-local methods; an
/// argument is flagged when its expression text equals the default spelled
/// at the same position of some overload.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let methods = local_method_table(root, source);
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| invocation_is_positional(*call))
        .flat_map(|call| {
            let Some(candidates) = callee_name(call, source).and_then(|name| methods.get(name))
            else {
                return Vec::new();
            };
            let arguments = invocation_arguments(call);
            if arguments.is_empty() {
                return Vec::new();
            }
            arguments
                .into_iter()
                .enumerate()
                .filter(|(index, argument)| {
                    let text = node_text(argument_expression(*argument), source);
                    candidates.iter().any(|method| {
                        parameter_units(*method, source)
                            .get(*index)
                            .and_then(|unit| unit.default_value)
                            .is_some_and(|default| node_text(default, source) == text)
                    })
                })
                .map(|(_, argument)| argument)
                .collect::<Vec<_>>()
        })
        .map(|argument| {
            issue(
                language,
                "S3254",
                "Remove this argument; it duplicates the parameter's default value.",
                range_of(argument, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3254_non_default_arguments_stay_clean() {
        let report = analyze_default(
            "class Sender\n{\n    public void Send(string body, int retries = 3)\n    {\n    }\n    public void Deliver()\n    {\n        Send(\"hello\", 5);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3254").is_empty());
    }

    #[test]
    fn s3254_named_arguments_stay_out_of_scope() {
        let report = analyze_default(
            "class Sender\n{\n    public void Send(string body, int retries = 3)\n    {\n    }\n    public void Deliver()\n    {\n        Send(body: \"hello\", retries: 3);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3254").is_empty());
    }

    #[test]
    fn s3254_flags_each_duplicated_default_argument() {
        let report = analyze_default(
            "class Sender\n{\n    public void Send(string body = \"x\", int retries = 3)\n    {\n    }\n    public void Deliver()\n    {\n        Send(\"x\", 3);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3254");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 8);
        assert_eq!(flagged[1].range.start.line, 8);
    }

    #[test]
    fn s3254_bool_default_only_flags_the_matching_spelling() {
        let report = analyze_default(
            "class Runner\n{\n    public void Run(bool verbose = true)\n    {\n    }\n    public void Go()\n    {\n        Run(true);\n        Run(false);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3254");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 8);
    }

    #[test]
    fn s3254_foreign_callees_stay_uncovered() {
        let report =
            analyze_default("static void Main()\n{\n    Console.WriteLine(\"hi\", 3);\n}\n");
        assert!(with_key(&report, "csharpsquid:S3254").is_empty());
    }
}
