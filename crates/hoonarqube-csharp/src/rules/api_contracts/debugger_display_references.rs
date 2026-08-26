use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{declared_method_names, field_and_property_names};
use crate::rules::literals::literal_inner_text;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::CALLABLE_BODY_OWNER_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4545 — `DebuggerDisplay` values naming missing members
/// render blank output.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for list in collect_kinds(root, &["attribute_list"]) {
        if is_error_tainted(list) {
            continue;
        }
        let mut cursor = list.walk();
        let display = list.children(&mut cursor).find(|attribute| {
            attribute
                .child_by_field_name("name")
                .is_some_and(|name| simple_name(node_text(name, source)) == "DebuggerDisplay")
        });
        let Some(display) = display else {
            continue;
        };
        let Some(literal) = collect_kinds(display, &["string_literal"]).first().copied() else {
            continue;
        };
        let Some(owner) = list.parent().filter(|parent| {
            TYPE_DECLARATION_KINDS.contains(&parent.kind())
                || CALLABLE_BODY_OWNER_KINDS.contains(&parent.kind())
        }) else {
            continue;
        };
        let known = declared_member_names(owner, source);
        for member in debugger_display_members(literal_inner_text(literal, source)) {
            if !known.contains(member) {
                issues.push(issue(
                    language,
                    "S4545",
                    format!("'DebuggerDisplay' references missing member '{member}'."),
                    range_of(list, source),
                ));
            }
        }
    }
    issues
}

/// `{Member}` references inside a `DebuggerDisplay` value.
fn debugger_display_members(value: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let token = &after[..close];
                let bare = token.split([',', ':', '(']).next().unwrap_or(token).trim();
                if !bare.is_empty() {
                    members.push(bare);
                }
                rest = &after[close + 1..];
            }
            None => break,
        }
    }
    members
}

/// Field, property, and method names declared directly by a declaration.
fn declared_member_names(declaration: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = declared_method_names(declaration, source);
    names.extend(field_and_property_names(declaration, source));
    names
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4545_format_specifiers_and_method_forms_resolve() {
        let report = analyze_default(
            "[DebuggerDisplay(\"{Name,nq} {Compute()}\")]\nclass Card\n{\n    public string Name { get; set; }\n    int Compute() => 1;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4545").is_empty());
    }

    #[test]
    fn s4545_flags_missing_member_behind_method_form() {
        let report = analyze_default(
            "[DebuggerDisplay(\"{Missing()}\")]\nclass Card\n{\n    public string Name { get; set; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4545");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Missing'"));
    }

    #[test]
    fn s4545_ignores_attributes_on_non_type_owners() {
        let report = analyze_default(
            "class Card\n{\n    [DebuggerDisplay(\"{Nope}\")]\n    public string label;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4545").is_empty());
    }
}
