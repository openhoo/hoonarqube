use crate::CsLanguage;
use crate::cst::{
    ancestors_of, canonical_identifier, collect_kinds, containing_namespace, is_error_tainted,
    issue, node_text, range_of,
};
use crate::rules::expressions::{enclosing_callable, enclosing_type, resolved_identifier_type};
use crate::symbol_table::{UsageSymbols, build_usage_symbols};
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

/// csharpsquid:S1128 — remove a using only when this syntax-only analyzer can
/// prove that no binding or unknown imported symbol can depend on it.
///
/// A tree-sitter parse cannot identify which external namespace owns `List` or
/// an extension method such as `OfType`.  Such references therefore keep every
/// applicable ordinary import conservative; source-bound names, fully
/// qualified paths, and genuinely reference-free scopes are classified as
/// unused.
pub(crate) fn check<'t>(root: Node<'t>, source: &'t str, language: CsLanguage) -> Vec<Issue> {
    let directives: Vec<Node<'t>> = collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|directive| !is_error_tainted(*directive))
        .collect();
    if directives.is_empty() {
        return Vec::new();
    }

    let symbols = build_usage_symbols(root, source);
    let references = usage_references(root, source, &symbols);

    directives
        .into_iter()
        .filter_map(|directive| {
            let kind = using_kind(directive, source)?;
            let used = match kind {
                UsingKind::Global => return None,
                UsingKind::Alias { name } => {
                    alias_is_used(root, directive, name, source, &symbols, &references)
                }
                UsingKind::Namespace(target) => {
                    namespace_using_is_used(root, directive, target, source, &symbols, &references)
                }
                UsingKind::Static => {
                    static_using_is_used(root, directive, source, &symbols, &references)
                }
            };
            (!used).then_some(directive)
        })
        .map(|directive| {
            issue(
                language,
                "S1128",
                "Remove this unnecessary 'using'.",
                range_of(directive, source),
            )
        })
        .collect()
}

#[derive(Clone, Copy)]
enum UsingKind<'a> {
    Global,
    Namespace(&'a str),
    Static,
    Alias { name: &'a str },
}

/// Namespace targets remain available for qualified-name matching.  Aliases
/// are tracked only by their introduced name; their target is not an alias
/// spelling.
fn using_kind<'a>(directive: Node<'_>, source: &'a str) -> Option<UsingKind<'a>> {
    let text = node_text(directive, source).trim();
    if let Some(after_global) = text.strip_prefix("global")
        && after_global.chars().next().is_some_and(char::is_whitespace)
        && after_global.trim_start().starts_with("using")
    {
        return Some(UsingKind::Global);
    }

    let mut inner = text.strip_prefix("using")?.trim();
    inner = inner.strip_suffix(';')?.trim();
    let mut is_static = false;
    loop {
        if let Some(rest) = strip_using_keyword(inner, "unsafe") {
            inner = rest;
            continue;
        }
        if let Some(rest) = strip_using_keyword(inner, "static") {
            inner = rest;
            is_static = true;
            continue;
        }
        break;
    }

    if let Some((alias, target)) = inner.split_once('=') {
        let alias = canonical_identifier(alias.trim());
        if alias.is_empty() || target.trim().is_empty() {
            return None;
        }
        return Some(UsingKind::Alias { name: alias });
    }
    if inner.is_empty() {
        return None;
    }
    Some(if is_static {
        UsingKind::Static
    } else {
        UsingKind::Namespace(inner)
    })
}

fn strip_using_keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(keyword)?;
    if rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace) {
        Some(rest.trim_start())
    } else {
        None
    }
}
/// A using directive applies to its namespace body and lexically nested
/// namespace bodies, but never to an unrelated sibling namespace.
fn using_directive_applies(using: Node<'_>, use_site: Node<'_>) -> bool {
    let using_namespace = ancestors_of(using).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "namespace_declaration" | "file_scoped_namespace_declaration"
        )
    });
    let use_namespace = ancestors_of(use_site).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "namespace_declaration" | "file_scoped_namespace_declaration"
        )
    });
    match using_namespace {
        None => true,
        Some(namespace) => use_namespace.is_some_and(|use_namespace| {
            namespace.id() == use_namespace.id()
                || ancestors_of(use_namespace).any(|ancestor| ancestor.id() == namespace.id())
        }),
    }
}

/// `UsageSymbols` owns the existing declaration-aware classification.  Query
/// its indexed names rather than rebuilding a lexical reference scan here.
fn usage_references<'t>(
    root: Node<'t>,
    source: &'t str,
    symbols: &UsageSymbols<'t>,
) -> Vec<Node<'t>> {
    let names: HashSet<String> = collect_kinds(root, &["identifier"])
        .into_iter()
        .map(|identifier| canonical_identifier(node_text(identifier, source)).to_owned())
        .collect();
    let mut references: Vec<Node<'t>> = names
        .into_iter()
        .flat_map(|name| {
            symbols
                .uses_of(&name)
                .filter(|reference| !inside_using_directive(*reference))
        })
        .collect();
    references.extend(
        collect_kinds(root, &["parameter"])
            .into_iter()
            .filter_map(|parameter| parameter.child_by_field_name("type"))
            .flat_map(|type_node| collect_kinds(type_node, &["identifier"]))
            .filter(|reference| !inside_using_directive(*reference)),
    );
    references.sort_by_key(tree_sitter::Node::start_byte);
    references.dedup_by_key(|reference| reference.id());
    references
}

fn inside_using_directive(node: Node<'_>) -> bool {
    ancestors_of(node).any(|ancestor| ancestor.kind() == "using_directive")
}

fn namespace_using_is_used<'t>(
    root: Node<'t>,
    directive: Node<'t>,
    target: &str,
    source: &'t str,
    symbols: &UsageSymbols<'t>,
    references: &[Node<'t>],
) -> bool {
    references.iter().copied().any(|reference| {
        if !using_directive_applies(directive, reference)
            || !may_be_namespace_reference(reference)
            || is_source_bound_reference(root, reference, source, symbols, true)
        {
            return false;
        }
        if qualified_reference_matches(reference, target, source) {
            // A fully qualified path does not depend on this using directive.
            return false;
        }
        if canonical_identifier(node_text(reference, source)) == target {
            return true;
        }
        // An unresolved short or partially qualified external type/member can
        // belong to this namespace, so retain the import conservatively.
        true
    })
}

fn static_using_is_used<'t>(
    root: Node<'t>,
    directive: Node<'t>,
    source: &'t str,
    symbols: &UsageSymbols<'t>,
    references: &[Node<'t>],
) -> bool {
    references.iter().copied().any(|reference| {
        using_directive_applies(directive, reference)
            && may_be_static_reference(reference)
            && !is_source_bound_reference(root, reference, source, symbols, true)
    })
}

fn alias_is_used<'t>(
    root: Node<'t>,
    directive: Node<'t>,
    name: &str,
    source: &'t str,
    symbols: &UsageSymbols<'t>,
    references: &[Node<'t>],
) -> bool {
    references.iter().copied().any(|reference| {
        let type_position = is_type_reference(reference);
        canonical_identifier(node_text(reference, source)) == name
            && using_directive_applies(directive, reference)
            && !is_member_name(reference)
            && (type_position
                || !is_source_bound_reference(root, reference, source, symbols, false))
    })
}

fn may_be_namespace_reference(node: Node<'_>) -> bool {
    is_member_name(node)
        || is_type_reference(node)
        || node.parent().is_some_and(|parent| {
            parent.kind() == "member_access_expression"
                && parent.child_by_field_name("expression") == Some(node)
        })
}

fn qualified_reference_matches(reference: Node<'_>, target: &str, source: &str) -> bool {
    let target = compact_path(target);
    if target.is_empty() {
        return false;
    }
    let mut candidate = Some(reference);
    while let Some(node) = candidate {
        if matches!(
            node.kind(),
            "qualified_name" | "alias_qualified_name" | "member_access_expression"
        ) {
            let path = compact_path(node_text(node, source));
            if path == target
                || path
                    .strip_prefix(&target)
                    .is_some_and(|suffix| suffix.starts_with('.'))
            {
                return true;
            }
        }
        candidate = node.parent();
    }
    false
}

fn compact_path(text: &str) -> String {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    compact
        .strip_prefix("global::")
        .unwrap_or(&compact)
        .to_owned()
}

fn may_be_static_reference(node: Node<'_>) -> bool {
    !is_member_name(node) && !is_qualified_name_segment(node)
}

fn is_type_reference(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "attribute" && parent.child_by_field_name("name") == Some(node)
    }) || ancestors_of(node).any(|ancestor| {
        matches!(
            ancestor.kind(),
            "type" | "type_argument_list" | "generic_name" | "base_list"
        )
    }) || ancestors_of(node).any(|ancestor| {
        ["type", "returns"].into_iter().any(|field| {
            ancestor
                .child_by_field_name(field)
                .is_some_and(|type_node| {
                    type_node.id() == node.id()
                        || ancestors_of(node).any(|parent| parent.id() == type_node.id())
                })
        })
    })
}

fn is_member_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if matches!(
        parent.kind(),
        "member_access_expression" | "member_binding_expression"
    ) && parent.child_by_field_name("name") == Some(node)
    {
        return true;
    }
    parent.kind() == "generic_name"
        && parent.parent().is_some_and(|access| {
            access.kind() == "member_access_expression"
                && access.child_by_field_name("name") == Some(parent)
        })
}

fn is_qualified_name_segment(node: Node<'_>) -> bool {
    ancestors_of(node)
        .any(|ancestor| matches!(ancestor.kind(), "qualified_name" | "alias_qualified_name"))
}

/// Names known to bind within this source are not evidence for an imported
/// namespace.  Everything else remains an explicit unresolved-import case.
fn is_source_bound_reference<'t>(
    root: Node<'t>,
    reference: Node<'t>,
    source: &'t str,
    symbols: &UsageSymbols<'t>,
    aliases_are_bindings: bool,
) -> bool {
    let wanted = canonical_identifier(node_text(reference, source));
    if is_type_reference(reference) {
        return (aliases_are_bindings && visible_alias_name(root, reference, wanted, source))
            || source_type_visible(reference, wanted, source, symbols);
    }
    (aliases_are_bindings && visible_alias_name(root, reference, wanted, source))
        || resolved_identifier_type(reference, source).is_some()
        || source_member_visible(reference, wanted, symbols)
        || source_local_function_visible(root, reference, wanted, source)
}

fn visible_alias_name<'t>(
    root: Node<'t>,
    reference: Node<'t>,
    wanted: &str,
    source: &'t str,
) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter_map(|directive| using_kind(directive, source).map(|kind| (directive, kind)))
        .any(|(directive, kind)| {
            matches!(kind, UsingKind::Alias { name } if name == wanted)
                && using_directive_applies(directive, reference)
        })
}

fn source_type_visible<'t>(
    use_site: Node<'t>,
    wanted: &str,
    source: &'t str,
    symbols: &UsageSymbols<'t>,
) -> bool {
    let namespace = containing_namespace(use_site, source);
    symbols.types.iter().any(|type_symbol| {
        let Some(name) = type_symbol.declaration.child_by_field_name("name") else {
            return false;
        };
        canonical_identifier(node_text(name, source)) == wanted
            && containing_namespace(type_symbol.declaration, source) == namespace
            && type_declaration_visible(type_symbol.declaration, use_site)
    })
}

fn type_declaration_visible(declaration: Node<'_>, use_site: Node<'_>) -> bool {
    let Some(declaration_owner) = enclosing_type(declaration) else {
        return true;
    };
    let Some(use_owner) = enclosing_type(use_site) else {
        return false;
    };
    use_owner.id() == declaration_owner.id()
        || ancestors_of(use_site).any(|ancestor| ancestor.id() == declaration_owner.id())
}

fn source_member_visible<'t>(
    reference: Node<'t>,
    wanted: &str,
    symbols: &UsageSymbols<'t>,
) -> bool {
    let Some(owner) = enclosing_type(reference) else {
        return false;
    };
    symbols
        .members
        .iter()
        .any(|member| member.owner.id() == owner.id() && member.name == wanted)
}

fn source_local_function_visible<'t>(
    root: Node<'t>,
    reference: Node<'t>,
    wanted: &str,
    source: &'t str,
) -> bool {
    let reference_owner = enclosing_callable(reference);
    collect_kinds(root, &["local_function_statement"])
        .into_iter()
        .filter(|declaration| {
            declaration
                .child_by_field_name("name")
                .is_some_and(|name| canonical_identifier(node_text(name, source)) == wanted)
        })
        .any(|declaration| {
            reference_owner.is_some_and(|owner| {
                enclosing_callable(declaration)
                    .is_some_and(|declaration_owner| declaration_owner.id() == owner.id())
            })
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1128_flags_each_segment_even_when_directives_share_it() {
        let report = analyze_default("using A.Tools;\nusing B.Tools;\nclass C\n{\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 2);
    }

    #[test]
    fn s1128_keeps_used_aliases() {
        let report = analyze_default(
            "using Repo = Acme.Data.Repository;\nclass C\n{\n    void M()\n    {\n        Repo.Load();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }

    #[test]
    fn s1128_keeps_aliases_in_nested_namespaces() {
        let report = analyze_default(
            "namespace Outer\n{\n    using Text = System.String;\n    namespace Inner\n    {\n        class C\n        {\n            Text value = \"\";\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }

    #[test]
    fn s1128_keeps_type_alias_when_member_shares_name() {
        let report = analyze_default(
            "using Timer = System.Threading.Timer;\nclass C\n{\n    Timer Timer;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }

    #[test]
    fn s1128_keeps_aliases_in_parameter_types() {
        let report = analyze_default(
            "using Text = System.String;\nclass C\n{\n    void M(Text value) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }

    #[test]
    fn s1128_flags_fully_qualified_namespace_imports_as_redundant() {
        let report = analyze_default(
            "using System.Xml.Linq;\nclass C\n{\n    object M() => System.Xml.Linq.XElement.Load(\"x\");\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_does_not_count_alias_target_tail_as_alias_usage() {
        let report =
            analyze_default("using Alias = System.IO.File;\nclass C\n{\n    File value;\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_audits_directives_nested_in_namespaces() {
        let report = analyze_default(
            "namespace N\n{\n    using System.Linq;\n    class C\n    {\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_leaves_global_usings_untouched() {
        let report = analyze_default("global using System.Threading;\nclass C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }

    #[test]
    fn s1128_ignores_comment_mentions() {
        let report = analyze_default(
            "using System.Net.Http;\n// Http traffic flows through the gateway.\nclass C\n{\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_keeps_generic_and_linq_imports_when_symbols_are_used() {
        let report = analyze_default(
            "using System.Collections.Generic;\nusing System.Linq;\nnamespace Controls { public class Base { public int Id; } public sealed class Derived : Base { public int Value => Id; } public static class C { public static void Use(Derived value) { _ = value.Value; } public static void M(List<Base> values) { foreach (Derived value in values.OfType<Derived>()) { Use(value); } } } }\n",
        );
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }

    #[test]
    fn s1128_keeps_static_imports_only_for_possible_static_members() {
        let used = analyze_default(
            "using static System.Math;\nclass C\n{\n    double M() => Sqrt(1);\n}\n",
        );
        assert!(with_key(&used, "csharpsquid:S1128").is_empty());

        let unused =
            analyze_default("using static System.Math;\nclass C\n{\n    double M() => 1;\n}\n");
        assert_eq!(with_key(&unused, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_does_not_count_shadowed_aliases_as_import_usage() {
        let report = analyze_default(
            "using Repo = Acme.Data.Repository;\nclass C\n{\n    void M()\n    {\n        var Repo = Build();\n        Repo.Load();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_distinguishes_namespace_type_collisions() {
        let report = analyze_default(
            "using System.Collections.Generic;\nnamespace N\n{\n    class List<T> { }\n    class C\n    {\n        List<int> values;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_keeps_unknown_imported_types_conservatively() {
        let report =
            analyze_default("using Vendor.Collections;\nclass C\n{\n    Unknown<int> values;\n}\n");
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }
}
