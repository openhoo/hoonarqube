use crate::CsLanguage;
use crate::cst::{
    ancestors_of, canonical_identifier, collect_kinds, containing_namespace, direct_attributes,
    issue, modifiers_of, node_text, range_of,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3005 — `ThreadStatic` only affects static fields; on an
/// instance field it silently does nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter_map(|field| {
            let attribute = direct_attributes(field).into_iter().find(|attribute| {
                attribute.child_by_field_name("name").is_some_and(|name| {
                    is_thread_static_name(root, field, node_text(name, source), source)
                })
            })?;
            (!has_modifier(&modifiers_of(field, source), "static")).then_some(attribute)
        })
        .map(|attribute| {
            issue(
                language,
                "S3005",
                "Remove the 'ThreadStatic' attribute from this definition.",
                range_of(attribute, source),
            )
        })
        .collect()
}

/// Recognize the existing unqualified syntax conservatively, plus exact
/// framework-qualified spellings.  A relative `System` is accepted only when
/// this source does not shadow it with a namespace or alias.
fn is_thread_static_name(root: Node<'_>, use_site: Node<'_>, name: &str, source: &str) -> bool {
    let normalized = name.trim().strip_suffix("Attribute").unwrap_or(name.trim());
    let parts: Vec<&str> = normalized.split('.').map(canonical_identifier).collect();
    match parts.as_slice() {
        ["ThreadStatic"] | ["global::System", "ThreadStatic"] => true,
        ["System", "ThreadStatic"] => !relative_system_is_shadowed(root, use_site, source),
        _ => false,
    }
}

fn relative_system_is_shadowed(root: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    has_system_alias(root, use_site, source)
        || has_system_namespace(root, use_site, source)
        || has_system_type(root, use_site, source)
}

fn has_system_alias(root: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .any(|using| {
            if !using_applies(using, use_site) {
                return false;
            }
            let text = node_text(using, source).trim();
            let text = text
                .strip_prefix("global")
                .map_or(text, |rest| rest.trim_start());
            let Some(inner) = text
                .strip_prefix("using")
                .and_then(|rest| rest.trim().strip_suffix(';'))
            else {
                return false;
            };
            inner
                .split_once('=')
                .is_some_and(|(alias, _)| canonical_identifier(alias.trim()) == "System")
        })
}

fn has_system_namespace(root: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    let use_namespace = containing_namespace(use_site, source);
    collect_kinds(
        root,
        &["namespace_declaration", "file_scoped_namespace_declaration"],
    )
    .into_iter()
    .any(|declaration| {
        let Some(name) = declaration.child_by_field_name("name") else {
            return false;
        };
        let declared_namespace = containing_namespace(declaration, source);
        let declared_name = node_text(name, source).trim();
        let full_name = if declared_namespace.is_empty() {
            declared_name.to_owned()
        } else {
            format!("{declared_namespace}.{declared_name}")
        };
        namespace_declares_system(&use_namespace, &full_name)
    })
}

fn has_system_type(root: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    let use_namespace = containing_namespace(use_site, source);
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .any(|declaration| {
            declaration
                .child_by_field_name("name")
                .is_some_and(|name| canonical_identifier(node_text(name, source)) == "System")
                && namespace_is_in_scope(&use_namespace, &containing_namespace(declaration, source))
        })
}

fn namespace_declares_system(use_namespace: &str, declared_namespace: &str) -> bool {
    let mut scope = use_namespace.to_owned();
    loop {
        let candidate = if scope.is_empty() {
            "System".to_owned()
        } else {
            format!("{scope}.System")
        };
        if candidate == declared_namespace {
            return true;
        }
        let Some((prefix, _)) = scope.rsplit_once('.') else {
            return declared_namespace == "System";
        };
        scope = prefix.to_owned();
    }
}

fn namespace_is_in_scope(use_namespace: &str, declaration_namespace: &str) -> bool {
    let mut scope = use_namespace;
    loop {
        if scope == declaration_namespace {
            return true;
        }
        let Some((prefix, _)) = scope.rsplit_once('.') else {
            return declaration_namespace.is_empty();
        };
        scope = prefix;
    }
}

fn using_applies(using: Node<'_>, use_site: Node<'_>) -> bool {
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3005_reports_qualified_thread_static_on_instance_field() {
        let report = analyze_default(
            "namespace Controls { public sealed class C { [System.ThreadStatic] public int field; public int Read() => field; } }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3005");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Remove the 'ThreadStatic' attribute from this definition."
        );
    }

    #[test]
    fn s3005_keeps_qualified_thread_static_on_static_field() {
        let report = analyze_default(
            "namespace Controls { public sealed class C { [System.ThreadStatic] public static int field; public int Read() => field; } }\n",
        );
        assert!(with_key(&report, "csharpsquid:S3005").is_empty());
    }

    #[test]
    fn s3005_does_not_match_differently_named_attribute_impostors() {
        let report = analyze_default("class C\n{\n    [ThreadStaticAlias]\n    int field;\n}\n");
        assert!(with_key(&report, "csharpsquid:S3005").is_empty());
    }

    #[test]
    fn s3005_reports_global_qualified_thread_static_attribute_suffix() {
        let report = analyze_default(
            "class C\n{\n    [global::System.ThreadStaticAttribute]\n    int field;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3005").len(), 1);
    }

    #[test]
    fn s3005_does_not_match_qualified_attribute_impostors() {
        let report = analyze_default("class C\n{\n    [Vendor.ThreadStatic]\n    int field;\n}\n");
        assert!(with_key(&report, "csharpsquid:S3005").is_empty());
    }

    #[test]
    fn s3005_ignores_relative_system_when_namespace_is_shadowed() {
        let report = analyze_default(
            "namespace Controls.System { public sealed class ThreadStaticAttribute : global::System.Attribute { } }\nnamespace Controls { public sealed class C { [System.ThreadStatic] public int field; } }\n",
        );
        assert!(with_key(&report, "csharpsquid:S3005").is_empty());
    }

    #[test]
    fn s3005_ignores_relative_system_when_alias_is_shadowed() {
        let report = analyze_default(
            "using System = Vendor;\nclass C\n{\n    [System.ThreadStatic]\n    int field;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3005").is_empty());
    }

    #[test]
    fn s3005_keeps_global_system_when_relative_system_is_shadowed() {
        let report = analyze_default(
            "namespace Controls.System { public sealed class ThreadStaticAttribute : global::System.Attribute { } }\nnamespace Controls { public sealed class C { [global::System.ThreadStatic] public int field; } }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3005").len(), 1);
    }
}
