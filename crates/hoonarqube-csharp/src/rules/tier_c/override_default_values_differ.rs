use super::support::{
    ParameterUnit, local_type_declarations, local_type_table, override_base_pairs, parameter_units,
};
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text,
    range_from_byte_offsets, range_of,
};
use crate::project_index::{ProjectTypeIndex, indexed_parameters};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::{has_modifier, type_parameter_list_of};
use crate::rules::naming::support::full_type_identity;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1006 — overrides changing or dropping a base method's
/// default value. Compiler-compatible local subset: class overrides and
/// file-local interface implementations, plus cross-file base classes when
/// a [`ProjectTypeIndex`] is supplied. Missing defaults and
/// explicit-interface defaults use the same bound parameter identity as
/// the compiler helper.
#[derive(Clone, Copy)]
enum PairKind {
    Override,
    ImplicitInterface,
    ExplicitInterface,
}
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut pairs = override_base_pairs(root, source)
        .into_iter()
        .map(|(method, base)| (method, base, PairKind::Override))
        .collect::<Vec<_>>();
    pairs.extend(interface_pairs(root, source));
    for (overriding, base, pair_kind) in pairs {
        let Some(difference) = first_default_difference_range(pair_kind, overriding, base, source)
        else {
            continue;
        };
        issues.push(issue(
            language,
            "S1006",
            difference.message(),
            difference.range,
        ));
    }
    issues.extend(cross_file_override_issues(
        root,
        source,
        language,
        options.project_type_index.as_deref(),
    ));
    issues
}

/// One default-value divergence: the anchor range plus the message the
/// reference platform emits for that divergence shape.
struct DefaultDifference {
    range: hoonarqube_ir::Range,
    added: bool,
}

impl DefaultDifference {
    fn message(&self) -> &'static str {
        if self.added {
            "Add the default parameter value defined in the overridden method."
        } else {
            "Use the default parameter value defined in the overridden method."
        }
    }
}

/// Overrides whose base class lives in another indexed file: the project
/// index supplies the base signatures (including written defaults) that a
/// per-file pass cannot see. File-local bases stay on the CST path above,
/// and the querying type's own partial declarations never count as bases.
fn cross_file_override_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    project: Option<&ProjectTypeIndex>,
) -> Vec<Issue> {
    let Some(project) = project else {
        return Vec::new();
    };
    let types = local_type_table(root, source);
    let mut issues = Vec::new();
    for declaration in local_type_declarations(root) {
        if declaration.kind() != "class_declaration" || is_error_tainted(declaration) {
            continue;
        }
        let Some(base_name) = base_simple_names(declaration, source).first().copied() else {
            continue;
        };
        if types.contains_key(base_name) {
            continue;
        }
        let own = (
            full_type_identity(declaration, source),
            type_parameter_list_of(declaration).map_or(0, |(_, count)| count),
        );
        for method in member_declarations_of_kind(declaration, "method_declaration") {
            if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "override")
            {
                continue;
            }
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            let derived = indexed_parameters(method, source);
            let units = parameter_units(method, source);
            for (base_type, base_method) in
                project.same_name_methods(base_name, node_text(name, source))
            {
                if base_type.is_interface
                    || (Some(base_type.identity.as_str()) == own.0.as_deref()
                        && base_type.arity == own.1)
                {
                    continue;
                }
                if !same_signature(&derived, &base_method.parameters) {
                    continue;
                }
                if let Some(difference) =
                    indexed_default_difference(&units, &derived, &base_method.parameters, source)
                {
                    issues.push(issue(
                        language,
                        "S1006",
                        difference.message(),
                        difference.range,
                    ));
                    break;
                }
            }
        }
    }
    issues
}

/// Whether an override's normalized signature equals the indexed base
/// signature exactly (`ref`-kind and type key per position).
fn same_signature(
    derived: &[crate::project_index::IndexedParameter],
    base: &[crate::project_index::IndexedParameter],
) -> bool {
    derived.len() == base.len()
        && derived
            .iter()
            .zip(base.iter())
            .all(|(left, right)| left.ref_kind == right.ref_kind && left.type_key == right.type_key)
}

/// The first default-value divergence between an override's CST
/// parameters and its indexed base parameters: a dropped default anchors
/// the parameter name, a changed default anchors the written value.
fn indexed_default_difference(
    units: &[ParameterUnit<'_>],
    derived: &[crate::project_index::IndexedParameter],
    base: &[crate::project_index::IndexedParameter],
    source: &str,
) -> Option<DefaultDifference> {
    units.iter().zip(derived.iter().zip(base.iter())).find_map(
        |(unit, (derived_parameter, base_parameter))| {
            let derived_default = unit
                .default_value
                .map(|value| node_text(value, source))
                .map(|text| {
                    text.chars()
                        .filter(|c| !c.is_whitespace())
                        .collect::<String>()
                })
                .or_else(|| derived_parameter.default_value.clone());
            match (unit.default_value, &base_parameter.default_value) {
                (None, Some(_)) => unit.name.map(|name| DefaultDifference {
                    range: range_of(name, source),
                    added: true,
                }),
                (Some(value), Some(base_value)) if Some(base_value) != derived_default.as_ref() => {
                    Some(DefaultDifference {
                        range: range_of(value, source),
                        added: false,
                    })
                }
                _ => None,
            }
        },
    )
}
fn first_default_difference_range(
    pair_kind: PairKind,
    overriding: Node<'_>,
    base: Node<'_>,
    source: &str,
) -> Option<DefaultDifference> {
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
) -> Option<DefaultDifference> {
    match pair_kind {
        PairKind::ExplicitInterface => unit.default_value.map(|value| DefaultDifference {
            range: default_clause_range(value, source),
            added: false,
        }),
        PairKind::ImplicitInterface => interface_default_difference(unit, base_unit, source),
        PairKind::Override => override_default_difference(unit, base_unit, source),
    }
}

fn interface_default_difference(
    unit: &ParameterUnit<'_>,
    base_unit: &ParameterUnit<'_>,
    source: &str,
) -> Option<DefaultDifference> {
    match (unit.default_value, base_unit.default_value) {
        (Some(value), None) => Some(DefaultDifference {
            range: default_clause_range(value, source),
            added: false,
        }),
        (None, Some(_)) => unit.name.map(|name| DefaultDifference {
            range: range_of(name, source),
            added: true,
        }),
        (Some(value), Some(base_value))
            if node_text(value, source) != node_text(base_value, source) =>
        {
            Some(DefaultDifference {
                range: range_of(value, source),
                added: false,
            })
        }
        _ => None,
    }
}

fn override_default_difference(
    unit: &ParameterUnit<'_>,
    base_unit: &ParameterUnit<'_>,
    source: &str,
) -> Option<DefaultDifference> {
    match (unit.default_value, base_unit.default_value) {
        (None, Some(_)) => unit.name.map(|name| DefaultDifference {
            range: range_of(name, source),
            added: true,
        }),
        (Some(value), Some(base_value))
            if node_text(value, source) != node_text(base_value, source) =>
        {
            Some(DefaultDifference {
                range: range_of(value, source),
                added: false,
            })
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
    fn s1006_dropped_default_flags_the_parameter_name() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public override void M(int x) {\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
        assert_eq!(
            found[0].message,
            "Add the default parameter value defined in the overridden method."
        );
    }

    #[test]
    fn s1006_cross_file_base_defaults_resolve_through_the_project_index() {
        let base = "public abstract class BulkCopy\n{\n    public abstract System.Threading.Tasks.Task WriteToServerAsync(System.Data.Common.DbDataReader source, System.Threading.CancellationToken cancellationToken = default);\n    public abstract System.Threading.Tasks.Task WriteToServerAsync(System.Data.DataTable source, System.Threading.CancellationToken cancellationToken = default);\n}\n";
        let derived = "class DynamicBulkCopy : BulkCopy\n{\n    public override System.Threading.Tasks.Task WriteToServerAsync(System.Data.Common.DbDataReader source, System.Threading.CancellationToken cancellationToken)\n        => null;\n    public override System.Threading.Tasks.Task WriteToServerAsync(System.Data.DataTable source, System.Threading.CancellationToken cancellationToken)\n        => null;\n}\n";
        let snapshots = [
            crate::semantic::SourceSnapshot::new(std::path::PathBuf::from("BulkCopy.cs"), base),
            crate::semantic::SourceSnapshot::new(
                std::path::PathBuf::from("DynamicBulkCopy.cs"),
                derived,
            ),
        ];
        let options = crate::AnalyzerOptions {
            project_type_index: Some(std::sync::Arc::new(crate::ProjectTypeIndex::build(
                &snapshots,
            ))),
            ..crate::AnalyzerOptions::default()
        };
        let report = crate::tests::analyze_options(derived, &options);
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 5);
        assert_eq!(
            found[0].message,
            "Add the default parameter value defined in the overridden method."
        );
    }

    #[test]
    fn s1006_cross_file_matching_defaults_stay_clean() {
        let base = "public abstract class BulkCopy\n{\n    public abstract System.Threading.Tasks.Task WriteToServerAsync(System.Data.Common.DbDataReader source, System.Threading.CancellationToken cancellationToken = default);\n}\n";
        let derived = "class DynamicBulkCopy : BulkCopy\n{\n    public override System.Threading.Tasks.Task WriteToServerAsync(System.Data.Common.DbDataReader source, System.Threading.CancellationToken cancellationToken = default)\n        => null;\n}\n";
        let snapshots = [
            crate::semantic::SourceSnapshot::new(std::path::PathBuf::from("BulkCopy.cs"), base),
            crate::semantic::SourceSnapshot::new(
                std::path::PathBuf::from("DynamicBulkCopy.cs"),
                derived,
            ),
        ];
        let options = crate::AnalyzerOptions {
            project_type_index: Some(std::sync::Arc::new(crate::ProjectTypeIndex::build(
                &snapshots,
            ))),
            ..crate::AnalyzerOptions::default()
        };
        let report = crate::tests::analyze_options(derived, &options);
        assert!(with_key(&report, KEY).is_empty());
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
