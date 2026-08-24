use super::support::invocation_is_positional;
use super::support::local_method_table;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2234 — arguments passed in a different order than the
/// parameters they bind to. Subset: fully positional calls against
/// file-local methods with exactly matching arity and no `params` tail; a
/// call is flagged when two argument identifiers spell each other's bound
/// parameter names. Calls into other files stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let methods = local_method_table(root, source);
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| invocation_is_positional(*call))
        .filter(|call| {
            let Some(candidates) = callee_name(*call, source).and_then(|name| methods.get(name))
            else {
                return false;
            };
            let arguments = invocation_arguments(*call);
            candidates.iter().any(|method| {
                let parameters = parameters_of(*method);
                parameters.len() == arguments.len()
                    && (0..arguments.len()).any(|first| {
                        ((first + 1)..arguments.len()).any(|second| {
                            swapped_argument_pair(&arguments, &parameters, first, second, source)
                        })
                    })
            })
        })
        .map(|call| {
            issue(
                language,
                "S2234",
                "Pass the arguments in the same order as the method's parameters.",
                range_of(call),
            )
        })
        .collect()
}

/// Whether the arguments at `first`/`second` spell the parameter names of
/// each other's positions.
fn swapped_argument_pair(
    arguments: &[Node<'_>],
    parameters: &[Node<'_>],
    first: usize,
    second: usize,
    source: &str,
) -> bool {
    let (Some(own), Some(other)) = (parameters.get(first), parameters.get(second)) else {
        return false;
    };
    let (Some(own_name), Some(other_name)) = (
        own.child_by_field_name("name"),
        other.child_by_field_name("name"),
    ) else {
        return false;
    };
    let own_name = node_text(own_name, source);
    let other_name = node_text(other_name, source);
    let left = argument_expression(arguments[first]);
    let right = argument_expression(arguments[second]);
    left.kind() == "identifier"
        && right.kind() == "identifier"
        && node_text(left, source) == other_name
        && node_text(right, source) == own_name
        && own_name != other_name
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2234_named_arguments_bypass_the_positional_gate() {
        let report = analyze_default(
            "class Calc\n{\n    public double Divide(double dividend, double divisor)\n    {\n        return dividend / divisor;\n    }\n    public void Quotient(double divisor, double dividend)\n    {\n        var ratio = Divide(dividend: divisor, divisor: dividend);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2234").is_empty());
    }

    #[test]
    fn s2234_non_identifier_arguments_stay_clean() {
        let report = analyze_default(
            "class Calc\n{\n    public void Scale(int factor, int offset)\n    {\n    }\n    public void Run()\n    {\n        Scale(offset + 1, factor);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2234").is_empty());
    }

    #[test]
    fn s2234_middle_swap_is_flagged() {
        let report = analyze_default(
            "class Calc\n{\n    public void Move(int x, int y, int z)\n    {\n    }\n    public void Run(int y, int x, int z)\n    {\n        Move(y, x, z);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2234");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 8);
    }

    #[test]
    fn s2234_literal_arguments_stay_clean() {
        let report = analyze_default(
            "class Calc\n{\n    public void Move(int x, int y)\n    {\n    }\n    public void Run()\n    {\n        Move(1, 2);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2234").is_empty());
    }

    #[test]
    fn s2234_flags_each_swapped_call_distinctly() {
        let report = analyze_default(
            "class Calc\n{\n    public void Swap(int left, int right)\n    {\n    }\n    public void Flip(int alpha, int beta)\n    {\n    }\n    public void Run()\n    {\n        Swap(right, left);\n        Flip(beta, alpha);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2234");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 11);
        assert_eq!(flagged[1].range.start.line, 12);
    }

    #[test]
    fn s2234_foreign_callees_stay_uncovered() {
        let report =
            analyze_default("static void Main()\n{\n    Console.WriteLine(count, size);\n}\n");
        assert!(with_key(&report, "csharpsquid:S2234").is_empty());
    }
}
