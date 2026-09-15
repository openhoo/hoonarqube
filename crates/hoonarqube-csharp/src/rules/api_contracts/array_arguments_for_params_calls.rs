use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{invocation_arguments, invocation_function};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Canonical BCL members whose final parameter is `params`. Qualified
/// spellings keep user methods sharing the short name out of scope.
const PARAMS_CALLEES: &[&str] = &[
    "string.Format",
    "String.Format",
    "System.String.Format",
    "string.Concat",
    "String.Concat",
    "System.String.Concat",
    "string.Join",
    "String.Join",
    "System.String.Join",
    "Console.WriteLine",
    "System.Console.WriteLine",
];

/// csharpsquid:S3878 — arrays built just to feed a `params` call waste an
/// allocation. Callees resolve through the BCL table above or through
/// file-local `params` declarations (the only user methods whose
/// `params`-ness a per-file analyzer can prove).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let local_params = local_params_methods(root, source);
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            invocation_function(*call).is_some_and(|function| {
                let function_text = crate::cst::node_text(function, source);
                let name = function_text
                    .strip_prefix("global::")
                    .unwrap_or(function_text);
                PARAMS_CALLEES.contains(&name)
                    || is_make_generic_method(*call, source)
                    || local_call_name(name)
                        .and_then(|bare| local_params.get(bare))
                        .is_some_and(|shape| shape.accepts(invocation_arguments(*call).len()))
            })
        })
        .filter_map(|call| {
            let arguments = invocation_arguments(call);
            let argument = *arguments.last()?;
            matches!(
                argument_expression(argument).kind(),
                "array_creation_expression" | "implicit_array_creation_expression"
            )
            .then_some(argument)
        })
        .map(|argument| {
            issue(
                language,
                "S3878",
                "Remove this array creation and simply pass the elements.",
                range_of(argument, source),
            )
        })
        .collect()
}

/// The bare method name of an unqualified or `this.`-qualified call:
/// `Build<T>` → `Build`, `this.Build` → `Build`. Calls through other
/// receivers (`obj.Build`) return `None` since they may bind a different
/// type's non-`params` method.
fn local_call_name(name: &str) -> Option<&str> {
    let name = name.strip_prefix("this.").unwrap_or(name);
    if name.contains('.') {
        return None;
    }
    Some(name.split('<').next().unwrap_or(name))
}

/// `MethodInfo.MakeGenericMethod(params Type[])` — the one BCL `params`
/// member reachable through a receiver expression rather than a
/// qualified name. The receiver must itself be a `GetMethod`-family call
/// (`typeof(T).GetMethod(…)`, `GetRuntimeMethod`, `GetDeclaredMethod`),
/// which keeps user methods sharing the name silent.
fn is_make_generic_method(call: Node<'_>, source: &str) -> bool {
    if crate::rules::expressions::callee_name(call, source) != Some("MakeGenericMethod") {
        return false;
    }
    crate::rules::expressions::invocation_receiver(call)
        .filter(|receiver| receiver.kind() == "invocation_expression")
        .and_then(|receiver| crate::rules::expressions::callee_name(receiver, source))
        .is_some_and(|callee| {
            matches!(
                callee,
                "GetMethod" | "GetRuntimeMethod" | "GetDeclaredMethod" | "GetMethods"
            )
        })
}

/// Overload shape of one file-local method name: the smallest fixed
/// parameter count among its `params` overloads, and the arities of
/// non-`params` overloads whose final parameter is itself an array (the
/// only overloads that can steal an array argument from `params`
/// binding).
#[derive(Default)]
struct ParamsShape {
    min_fixed: usize,
    competing: std::collections::HashSet<usize>,
    has_params: bool,
}

impl ParamsShape {
    /// Whether a call with `arguments` arguments provably binds the
    /// trailing array to a `params` parameter: some `params` overload has
    /// fewer fixed parameters than the argument count, and no
    /// array-accepting overload shares the arity.
    fn accepts(&self, arguments: usize) -> bool {
        self.has_params && arguments > self.min_fixed && !self.competing.contains(&arguments)
    }
}

/// File-local method names whose `params`-ness is provable. The parser
/// flattens `params T name` into `params`, `array_type`, `identifier`
/// siblings directly under `parameter_list`, so the check looks for that
/// trailing shape rather than a `parameter` node.
fn local_params_methods<'t>(
    root: Node<'t>,
    source: &'t str,
) -> std::collections::HashMap<&'t str, ParamsShape> {
    let mut shapes: std::collections::HashMap<&'t str, ParamsShape> =
        std::collections::HashMap::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let (Some(list), Some(name)) = (
            method.child_by_field_name("parameters"),
            method.child_by_field_name("name"),
        ) else {
            continue;
        };
        let mut cursor = list.walk();
        let children: Vec<Node<'t>> = list.children(&mut cursor).collect();
        let params_index = children
            .iter()
            .position(|child| child.kind() == "params" && !child.is_named())
            .filter(|index| {
                children
                    .get(index + 1)
                    .is_some_and(|ty| ty.kind() == "array_type")
                    && children
                        .get(index + 2)
                        .is_some_and(|name| name.kind() == "identifier")
            });
        let arity = children.iter().filter(|child| child.kind() == ",").count()
            + usize::from(children.iter().any(tree_sitter::Node::is_named));
        let shape = shapes
            .entry(crate::cst::node_text(name, source))
            .or_default();
        if let Some(index) = params_index {
            let fixed = children[..index]
                .iter()
                .filter(|child| child.kind() == ",")
                .count();
            if shape.has_params {
                shape.min_fixed = shape.min_fixed.min(fixed);
            } else {
                shape.min_fixed = fixed;
            }
            shape.has_params = true;
        } else {
            let last_is_array = children
                .iter()
                .rposition(tree_sitter::Node::is_named)
                .is_some_and(|last| {
                    children[last].kind() == "array_type"
                        || children[last]
                            .child_by_field_name("type")
                            .is_some_and(|ty| ty.kind() == "array_type")
                });
            if last_is_array {
                shape.competing.insert(arity);
            }
        }
    }
    shapes
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3878_ignores_arrays_outside_invocation_arguments() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        int[] keep = new int[] { 1, 2 };\n        Use(keep);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3878").is_empty());
    }

    #[test]
    fn s3878_flags_trailing_arrays_of_known_params_calls() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"{0}{1}\", new[] { \"a\" }, new string[] { \"b\" });\n        joined = string.Join(\",\", new int[] { 3 });\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3878");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s3878_spares_non_trailing_arrays_and_unknown_callees() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(new string[] { \"a\" }, marker);\n        other = Use(new[] { 1, 2 });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3878").is_empty());
    }

    #[test]
    fn s3878_spares_user_methods_named_like_bcl_params_methods() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        formatter.Format(new[] { 1, 2 });\n        WriteLine(new[] { 3, 4 });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3878").is_empty());
    }

    #[test]
    fn s3878_accepts_qualified_bcl_type_spellings() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        System.String.Concat(new[] { \"a\", \"b\" });\n        global::System.Console.WriteLine(new object[] { 1 });\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3878").len(), 2);
    }

    #[test]
    fn s3878_flags_file_local_params_calls() {
        let report = analyze_default(
            "class A\n{\n    protected System.Action<T> Build<T>(System.Type type)\n        => Build<T>(new[] { type });\n    protected System.Action<T> Build<T>(params System.Type[] types) => null;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3878");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s3878_spares_calls_bound_by_array_overloads() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Use(new[] { 1 });\n    }\n    void Use(int[] values) { }\n    void Use(params object[] values) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3878").is_empty());
    }

    #[test]
    fn s3878_flags_direct_binding_array_to_params() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Use(new[] { 1 });\n    }\n    void Use(params int[] values) { }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3878").len(), 1);
    }
}
