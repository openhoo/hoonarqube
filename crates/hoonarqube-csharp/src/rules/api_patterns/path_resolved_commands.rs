use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{
    callee_name, expression_name, invocation_arguments, invocation_receiver,
};
use crate::rules::literals::literal_inner_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4036 — launching a bare command name resolves through
/// `PATH`, so which binary runs depends on the caller's environment.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            let receiver =
                invocation_receiver(*call).and_then(|base| expression_name(base, source));
            callee_name(*call, source) == Some("Start") && receiver == Some("Process")
        })
        .filter(|call| {
            let arguments = invocation_arguments(*call);
            arguments.len() == 1
                && arguments[0]
                    .children(&mut arguments[0].walk())
                    .find(tree_sitter::Node::is_named)
                    .is_some_and(|value| {
                        value.kind() == "string_literal" && {
                            let command = literal_inner_text(value, source);
                            !command.contains(['/', '\\']) && !command.starts_with('.')
                        }
                    })
        })
        .map(|call| {
            issue(
                language,
                "S4036",
                "Launch this command by explicit path instead of relying on 'PATH'.",
                range_of(call, source),
            )
        })
        .collect()
}
