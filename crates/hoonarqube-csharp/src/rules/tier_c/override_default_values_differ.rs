use super::support::{
    ParameterUnit, local_type_declarations, local_type_table, override_base_pairs, parameter_units,
};
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, issue, node_text, range_from_byte_offsets, range_of,
};
use crate::rules::expressions::member_declarations_of_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1006 — overrides changing a base method's default value.
/// Compiler-compatible local subset: class overrides and file-local interface
/// implementations. Missing defaults and explicit-interface defaults use the
/// same bound parameter identity as the compiler helper.
#[derive(Clone, Copy)]
enum PairKind {
    Override,
    ImplicitInterface,
    ExplicitInterface,
}
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut pairs = override_base_pairs(root, source)
        .into_iter()
        .map(|(method, base)| (method, base, PairKind::Override))
        .collect::<Vec<_>>();
    pairs.extend(interface_pairs(root, source));
    for (overriding, base, pair_kind) in pairs {
        let Some(range) = first_default_difference_range(pair_kind, overriding, base, source)
        else {
            continue;
        };
        issues.push(issue(
            language,
            "S1006",
            "Use the default parameter value defined in the overridden method.",
            range,
        ));
    }
    issues
}
fn first_default_difference_range(
    pair_kind: PairKind,
    overriding: Node<'_>,
    base: Node<'_>,
    source: &str,
) -> Option<hoonarqube_ir::Range> {
    let overriding_parameters = parameter_units(overriding, source);
    let base_parameters = parameter_units(base, source);
    overriding_parameters
        .iter()
        .zip(base_parameters.iter())
        .find_map(|(unit, base_unit)| default_difference_range(pair_kind, unit, base_unit, source))
}

fn default_difference_range(
    pair_kind: PairKind,
    unit: &ParameterUnit<'_>,
    base_unit: &ParameterUnit<'_>,
    source: &str,
) -> Option<hoonarqube_ir::Range> {
    match pair_kind {
        PairKind::ExplicitInterface => unit
            .default_value
            .map(|value| default_clause_range(value, source)),
        PairKind::ImplicitInterface => interface_default_difference(unit, base_unit, source),
        PairKind::Override => override_default_difference(unit, base_unit, source),
    }
}

fn interface_default_difference(
    unit: &ParameterUnit<'_>,
    base_unit: &ParameterUnit<'_>,
    source: &str,
) -> Option<hoonarqube_ir::Range> {
    match (unit.default_value, base_unit.default_value) {
        (Some(value), None) => Some(default_clause_range(value, source)),
        (None, Some(_)) => unit.name.map(|name| range_of(name, source)),
        (Some(value), Some(base_value))
            if node_text(value, source) != node_text(base_value, source) =>
        {
            Some(range_of(value, source))
        }
        _ => None,
    }
}

fn override_default_difference(
    unit: &ParameterUnit<'_>,
    base_unit: &ParameterUnit<'_>,
    source: &str,
) -> Option<hoonarqube_ir::Range> {
    match (unit.default_value, base_unit.default_value) {
        (Some(value), Some(base_value))
            if node_text(value, source) != node_text(base_value, source) =>
        {
            Some(range_of(value, source))
        }
        _ => None,
    }
}

enum ExplicitInterface<'a> {
    Absent,
    Unresolved,
    Resolved(Node<'a>),
}

fn explicit_interface<'a>(
    method: Node<'a>,
    types: &std::collections::HashMap<&'a str, Node<'a>>,
    source: &'a str,
) -> ExplicitInterface<'a> {
    let Some(specifier) = collect_kinds(method, &["explicit_interface_specifier"])
        .into_iter()
        .next()
    else {
        return ExplicitInterface::Absent;
    };
    let interface_name = node_text(specifier, source).trim_end_matches('.');
    match types
        .get(interface_name)
        .copied()
        .filter(|node| node.kind() == "interface_declaration")
    {
        Some(interface) => ExplicitInterface::Resolved(interface),
        None => ExplicitInterface::Unresolved,
    }
}

fn matching_interface_method<'a>(
    interface: Node<'a>,
    method: Node<'a>,
    name: Node<'a>,
    source: &'a str,
) -> Option<Node<'a>> {
    member_declarations_of_kind(interface, "method_declaration")
        .into_iter()
        .find(|candidate| {
            candidate
                .child_by_field_name("name")
                .is_some_and(|candidate_name| {
                    node_text(candidate_name, source) == node_text(name, source)
                        && parameter_units(*candidate, source).len()
                            == parameter_units(method, source).len()
                })
        })
}

fn append_interface_pair<'a>(
    pairs: &mut Vec<(Node<'a>, Node<'a>, PairKind)>,
    method: Node<'a>,
    interface: Node<'a>,
    name: Node<'a>,
    pair_kind: PairKind,
    source: &'a str,
) {
    if let Some(interface_method) = matching_interface_method(interface, method, name, source) {
        pairs.push((method, interface_method, pair_kind));
    }
}

fn append_implicit_interface_pair<'a>(
    pairs: &mut Vec<(Node<'a>, Node<'a>, PairKind)>,
    declaration: Node<'a>,
    method: Node<'a>,
    name: Node<'a>,
    types: &std::collections::HashMap<&'a str, Node<'a>>,
    source: &'a str,
) {
    for base_name in base_simple_names(declaration, source) {
        let Some(interface) = types
            .get(base_name)
            .copied()
            .filter(|node| node.kind() == "interface_declaration")
        else {
            continue;
        };
        if let Some(interface_method) = matching_interface_method(interface, method, name, source) {
            pairs.push((method, interface_method, PairKind::ImplicitInterface));
            break;
        }
    }
}

fn interface_pairs<'a>(root: Node<'a>, source: &'a str) -> Vec<(Node<'a>, Node<'a>, PairKind)> {
    let types = local_type_table(root, source);
    let mut pairs = Vec::new();
    for declaration in local_type_declarations(root) {
        if declaration.kind() != "class_declaration" {
            continue;
        }
        let methods = member_declarations_of_kind(declaration, "method_declaration");
        for method in methods.iter().copied() {
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            match explicit_interface(method, &types, source) {
                ExplicitInterface::Resolved(interface) => {
                    append_interface_pair(
                        &mut pairs,
                        method,
                        interface,
                        name,
                        PairKind::ExplicitInterface,
                        source,
                    );
                    continue;
                }
                ExplicitInterface::Unresolved | ExplicitInterface::Absent => {}
            }
            append_implicit_interface_pair(&mut pairs, declaration, method, name, &types, source);
        }
    }
    pairs
}

fn default_clause_range(value: Node<'_>, source: &str) -> hoonarqube_ir::Range {
    let start = value
        .parent()
        .filter(|parameter| parameter.kind() == "parameter")
        .and_then(|parameter| {
            let mut cursor = parameter.walk();
            parameter
                .children(&mut cursor)
                .find(|child| child.kind() == "=" && child.end_byte() <= value.start_byte())
                .map(|equals| equals.start_byte())
        })
        .unwrap_or(value.start_byte());
    range_from_byte_offsets(start, value.end_byte(), source)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S1006";

    #[test]
    fn s1006_minimal_class_without_overrides_is_clean() {
        let report = analyze_default("class C {\n    void M(int x = 1) {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_matching_defaults_stay_clean() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public override void M(int x = 1) {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_changed_default_value_flags_the_override_name() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public override void M(int x = 2) {\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
    }

    #[test]
    fn s1006_explicit_default_range_starts_at_equals() {
        let with_comment = analyze_default(
            "public interface I { void M(int x = /* note */ 1); }\npublic sealed class C : I { void I.M(int x = /* note */ 1) { } }\n",
        );
        let found = with_key(&with_comment, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[0].range.start.column, 43);
        assert_eq!(found[0].range.end.column, 57);

        let compact = analyze_default(
            "public interface I { void M(int x=1); }\npublic sealed class C : I { void I.M(int x=1) { } }\n",
        );
        let found = with_key(&compact, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[0].range.start.column, 42);
        assert_eq!(found[0].range.end.column, 44);
    }

    #[test]
    fn s1006_missing_default_on_either_side_is_uncovered() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x) {\n    }\n}\nclass D : B {\n    public override void M(int x = 2) {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_non_override_same_signature_is_ignored() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public new void M(int x = 2) {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
