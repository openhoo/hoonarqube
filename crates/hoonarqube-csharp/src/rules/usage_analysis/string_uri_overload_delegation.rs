use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::structure::name_anchor;
use crate::symbol_table::has_contract_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3997 — string overloads beside Uri overloads delegate to
/// the Uri version instead of re-implementing it.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut groups: std::collections::HashMap<&str, Vec<Node>> = std::collections::HashMap::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        if let Some(name) = method.child_by_field_name("name") {
            groups
                .entry(node_text(name, source))
                .or_default()
                .push(method);
        }
    }
    let mut issues = Vec::new();
    for methods in groups.into_values() {
        if methods.len() < 2 {
            continue;
        }
        let takes_uri = |method: Node| {
            parameters_of(method).iter().any(|parameter| {
                parameter
                    .child_by_field_name("type")
                    .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "Uri")
            })
        };
        if !methods.iter().copied().any(takes_uri) {
            continue;
        }
        for method in methods {
            if takes_uri(method)
                || has_contract_modifier(&modifiers_of(method, source))
                || collect_kinds(method, &["object_creation_expression"])
                    .into_iter()
                    .any(|creation| {
                        creation
                            .child_by_field_name("type")
                            .is_some_and(|type_node| {
                                simple_name(node_text(type_node, source)) == "Uri"
                            })
                    })
            {
                continue;
            }
            issues.push(issue(
                language,
                "S3997",
                "Refactor this method so it invokes the overload accepting a 'System.Uri' parameter.",
                range_of(name_anchor(method), source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3997_minimal_single_overload_produces_no_findings() {
        let report = analyze_default(
            "class C\n{\n    public System.Uri Load(System.Uri value)\n    {\n        return value;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3997").is_empty());
    }

    #[test]
    fn s3997_requires_a_uri_taking_sibling_overload() {
        let report = analyze_default(
            "class C\n{\n    public System.Uri Load(string value)\n    {\n        return System.Text.RegularExpressions.Regex.Unescape(value);\n    }\n\n    public System.Uri Save(string value)\n    {\n        return System.Text.RegularExpressions.Regex.Unescape(value);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3997").is_empty());
    }

    #[test]
    fn s3997_flags_each_group_regardless_of_hash_order() {
        let report = analyze_default(
            "class C\n{\n    public System.Uri Load(System.Uri value)\n    {\n        return value;\n    }\n\n    public System.Uri Load(string text)\n    {\n        return System.Text.RegularExpressions.Regex.Unescape(text);\n    }\n\n    public System.Uri Save(System.Uri value)\n    {\n        return value;\n    }\n\n    public System.Uri Save(string text)\n    {\n        return System.Text.RegularExpressions.Regex.Unescape(text);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3997");
        assert_eq!(flagged.len(), 2);
        let mut lines: Vec<_> = flagged.iter().map(|found| found.range.start.line).collect();
        lines.sort_unstable();
        assert_eq!(lines, [8, 18]);
        assert!(flagged.iter().all(|found| {
            found.message
                == "Refactor this method so it invokes the overload accepting a 'System.Uri' parameter."
        }));
    }

    #[test]
    fn s3997_ignores_groups_where_every_overload_takes_uri() {
        let report = analyze_default(
            "class C\n{\n    public System.Uri Load(System.Uri value)\n    {\n        return value;\n    }\n\n    public System.Uri Load(System.Uri value, int mode)\n    {\n        return value;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3997").is_empty());
    }

    #[test]
    fn s3997_honors_contract_modifiers_and_local_delegation() {
        let virtual_overload = analyze_default(
            "class C\n{\n    public System.Uri Load(System.Uri value)\n    {\n        return value;\n    }\n\n    public virtual System.Uri Load(string text)\n    {\n        return System.Text.RegularExpressions.Regex.Unescape(text);\n    }\n}\n",
        );
        assert!(with_key(&virtual_overload, "csharpsquid:S3997").is_empty());

        let via_local = analyze_default(
            "class C\n{\n    public System.Uri Load(System.Uri value)\n    {\n        return value;\n    }\n\n    public System.Uri Load(string text)\n    {\n        var parsed = new System.Uri(text);\n        return parsed;\n    }\n}\n",
        );
        assert!(with_key(&via_local, "csharpsquid:S3997").is_empty());
    }
}
