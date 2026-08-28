use super::support::name_anchor;
use super::support::type_has_no_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::declaration_kind_word;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2094 — classes and records carry members.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["class_declaration", "record_declaration"];
    let mut issues = Vec::new();
    for type_declaration in collect_kinds(root, &KINDS) {
        let positional_record = type_declaration.kind() == "record_declaration"
            && type_declaration
                .children(&mut type_declaration.walk())
                .any(|child| child.kind() == "parameter_list");
        if is_error_tainted(type_declaration)
            || has_modifier(&modifiers_of(type_declaration, source), "partial")
            || positional_record
        {
            continue;
        }
        if type_has_no_members(type_declaration) {
            issues.push(issue(
                language,
                "S2094",
                format!(
                    "Remove this empty {}, write its code or make it an \"interface\".",
                    declaration_kind_word(type_declaration.kind())
                ),
                range_of(name_anchor(type_declaration), source),
            ));
        }
    }
    issues
}
