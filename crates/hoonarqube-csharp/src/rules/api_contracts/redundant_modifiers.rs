use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::{accessibility_rank, has_modifier};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::{accessors_of, name_anchor};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2333 — single-part `partial` types and accessors repeating
/// their property's visibility carry dead modifiers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = redundant_partial_issues(root, source, language);
    issues.extend(redundant_unsafe_issues(root, source, language));
    issues.extend(redundant_accessor_issues(root, source, language));
    issues
}

fn redundant_partial_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    use std::collections::BTreeMap;
    let declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    let mut name_counts: BTreeMap<(String, String), u32> = BTreeMap::new();
    for type_node in &declarations {
        let key = (
            (*type_node).kind().to_string(),
            type_node
                .child_by_field_name("name")
                .map(|name| node_text(name, source).to_string())
                .unwrap_or_default(),
        );
        *name_counts.entry(key).or_insert(0) += 1;
    }
    let mut issues = Vec::new();
    for type_node in &declarations {
        if is_error_tainted(*type_node)
            || !has_modifier(&modifiers_of(*type_node, source), "partial")
        {
            continue;
        }
        let key = (
            (*type_node).kind().to_string(),
            type_node
                .child_by_field_name("name")
                .map(|name| node_text(name, source).to_string())
                .unwrap_or_default(),
        );
        if name_counts.get(&key).copied().unwrap_or(0) == 1 {
            issues.push(issue(
                language,
                "S2333",
                "'partial' is gratuitous in this context.",
                modifier_range(*type_node, source, "partial")
                    .unwrap_or_else(|| range_of(name_anchor(*type_node), source)),
            ));
        }
    }
    issues
}

fn redundant_unsafe_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "method_declaration",
            "constructor_declaration",
            "operator_declaration",
            "conversion_operator_declaration",
        ],
    ) {
        if has_modifier(&modifiers_of(declaration, source), "unsafe")
            && !contains_unsafe_construct(declaration)
            && let Some(range) = modifier_range(declaration, source, "unsafe")
        {
            issues.push(issue(
                language,
                "S2333",
                "'unsafe' is redundant in this context.",
                range,
            ));
        }
    }
    issues
}

fn redundant_accessor_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        let property_rank = accessibility_rank(&modifiers_of(property, source));
        if property_rank == 0 {
            continue;
        }
        let accessors = accessors_of(property);
        let uniformly_redundant = accessors
            .iter()
            .all(|accessor| accessibility_rank(&modifiers_of(*accessor, source)) == property_rank);
        if !uniformly_redundant {
            continue;
        }
        for accessor in accessors {
            if accessibility_rank(&modifiers_of(accessor, source)) == property_rank {
                issues.push(issue(
                    language,
                    "S2333",
                    "Remove this redundant accessibility modifier.",
                    range_of(accessor, source),
                ));
            }
        }
    }
    issues
}

fn modifier_range(
    declaration: Node<'_>,
    source: &str,
    wanted: &str,
) -> Option<hoonarqube_ir::Range> {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "modifier" && node_text(*child, source) == wanted)
        .map(|node| range_of(node, source))
}

fn contains_unsafe_construct(declaration: Node<'_>) -> bool {
    !collect_kinds(
        declaration,
        &[
            "pointer_type",
            "pointer_indirection_expression",
            "address_of_expression",
            "sizeof_expression",
            "stackalloc_expression",
            "fixed_statement",
        ],
    )
    .is_empty()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2333_matches_accessor_visibility_against_property_rank() {
        let report = analyze_default(
            "class A\n{\n    public int Both { public get; public set; }\n    public int Mixed { public get; private set; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2333");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 3);
    }

    #[test]
    fn s2333_counts_partials_per_type_kind() {
        let report = analyze_default(
            "partial class Duo { }\npartial struct Duo { }\npartial struct Duo { }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2333");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }
}
