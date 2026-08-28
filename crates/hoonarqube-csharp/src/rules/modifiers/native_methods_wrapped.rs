use super::support::{has_any_attribute, has_modifier};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::callee_name;
use crate::rules::structure::{body_of, name_anchor};
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

/// csharpsquid:S4200 — native entry points must be private and their managed
/// wrappers must do more than forward arguments directly.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let native_names: HashSet<&str> = collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| {
            let modifiers = modifiers_of(*method, source);
            has_modifier(&modifiers, "extern")
                && has_any_attribute(*method, source, &["DllImport"])
                && !has_modifier(&modifiers, "public")
        })
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect();

    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if has_modifier(&modifiers, "extern") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        if !collect_kinds(body, &["if_statement", "switch_statement", "try_statement"]).is_empty() {
            continue;
        }
        let Some(native_name) = collect_kinds(body, &["invocation_expression"])
            .into_iter()
            .filter_map(|invocation| callee_name(invocation, source))
            .find(|name| native_names.contains(name))
        else {
            continue;
        };
        issues.push(issue(
            language,
            "S4200",
            format!("Make this wrapper for native method '{native_name}' less trivial."),
            range_of(name_anchor(method), source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4200_flags_trivial_private_native_wrapper() {
        let report = analyze_default(
            "class Audio\n{\n    [DllImport(\"native\")]\n    private static extern int Play(string name);\n\n    public static int Chime(string name)\n    {\n        return Play(name);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4200");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Make this wrapper for native method 'Play' less trivial."
        );
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s4200_accepts_wrapper_with_validation() {
        let report = analyze_default(
            "class Audio\n{\n    [DllImport(\"native\")]\n    private static extern int Play(string name);\n\n    public static int Chime(string name)\n    {\n        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException();\n        return Play(name);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4200").is_empty());
    }
}
