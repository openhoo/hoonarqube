use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4210 — `WinForms` entry points are marked `[STAThread]`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let winforms_file =
        source.contains("System.Windows.Forms") || source.contains("Application.Run");
    if !winforms_file {
        return Vec::new();
    }
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| !is_error_tainted(*method))
        .filter(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "Main")
        })
        .filter(|method| !has_any_attribute(*method, source, &["STAThread"]))
        .map(|method| {
            issue(
                language,
                "S4210",
                "Mark the WinForms entry point with '[STAThread]'.",
                range_of(name_anchor(method), source),
            )
        })
        .collect()
}
