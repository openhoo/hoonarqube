use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    callee_name, enclosing_callable, expression_name, invocation_arguments, invocation_receiver,
    resolved_identifier_type,
};
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3011 — reflecting over non-public members escalates
/// accessibility beyond what the type author exposed.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            REFLECTION_MEMBER_LOOKUPS.contains(&canonical(callee_name(*call, source).unwrap_or("")))
        })
        .filter(|call| {
            invocation_receiver(*call).is_some_and(|receiver| {
                is_system_type_expression(receiver, root, source, call.start_byte())
            })
        })
        .filter_map(|call| binding_flags_argument(call, root, source))
        .map(|flags| {
            issue(
                language,
                "S3011",
                "Make sure that this accessibility bypass is safe here.",
                range_of(flags, source),
            )
        })
        .collect()
}

/// `System.Type` APIs accepting `BindingFlags`. Singular and plural forms
/// deliberately stay explicit so similarly named application methods do not
/// become findings.
const REFLECTION_MEMBER_LOOKUPS: [&str; 15] = [
    "GetMethod",
    "GetMethods",
    "GetField",
    "GetFields",
    "GetProperty",
    "GetProperties",
    "GetEvent",
    "GetEvents",
    "GetConstructor",
    "GetConstructors",
    "GetMember",
    "GetMembers",
    "GetNestedType",
    "GetNestedTypes",
    "InvokeMember",
];

fn canonical(name: &str) -> &str {
    name.strip_prefix('@').unwrap_or(name)
}

fn is_system_type_expression(
    expression: Node<'_>,
    root: Node<'_>,
    source: &str,
    before: usize,
) -> bool {
    match expression.kind() {
        "typeof_expression" => true,
        "invocation_expression" => {
            canonical(callee_name(expression, source).unwrap_or("")) == "GetType"
        }
        "identifier" => {
            resolved_identifier_type(expression, source).is_some_and(|ty| simple_name(ty) == "Type")
                || variable_initializer(expression, root, source, before).is_some_and(
                    |initializer| {
                        is_system_type_expression(
                            initializer,
                            root,
                            source,
                            initializer.start_byte(),
                        )
                    },
                )
        }
        "parenthesized_expression" | "cast_expression" => expression
            .named_child(expression.named_child_count().saturating_sub(1))
            .is_some_and(|inner| is_system_type_expression(inner, root, source, before)),
        _ => false,
    }
}

fn binding_flags_argument<'t>(
    invocation: Node<'t>,
    root: Node<'t>,
    source: &str,
) -> Option<Node<'t>> {
    invocation_arguments(invocation)
        .into_iter()
        .find_map(|argument| {
            let evidence = binding_flag_evidence(
                argument,
                root,
                source,
                invocation.start_byte(),
                &mut Vec::new(),
            );
            (evidence.non_public.is_some() && evidence.has_scope).then_some(evidence.non_public?)
        })
}

#[derive(Default)]
struct BindingFlagEvidence<'t> {
    non_public: Option<Node<'t>>,
    has_scope: bool,
}

fn binding_flag_evidence<'t>(
    expression: Node<'t>,
    root: Node<'t>,
    source: &str,
    before: usize,
    resolving: &mut Vec<String>,
) -> BindingFlagEvidence<'t> {
    if expression.kind() == "member_access_expression" {
        return match canonical(expression_name(expression, source).unwrap_or("")) {
            "NonPublic" => BindingFlagEvidence {
                non_public: Some(expression),
                has_scope: false,
            },
            "Instance" | "Static" => BindingFlagEvidence {
                non_public: None,
                has_scope: true,
            },
            _ => BindingFlagEvidence::default(),
        };
    }
    if expression.kind() == "identifier" {
        let name = canonical(node_text(expression, source));
        let statically_imported = has_static_binding_flags_import(root, source);
        if name == "NonPublic" && statically_imported {
            return BindingFlagEvidence {
                non_public: Some(expression),
                has_scope: false,
            };
        }
        if matches!(name, "Instance" | "Static") && statically_imported {
            return BindingFlagEvidence {
                non_public: None,
                has_scope: true,
            };
        }
        if resolving.iter().any(|resolved| resolved == name) {
            return BindingFlagEvidence::default();
        }
        if let Some(initializer) = variable_initializer(expression, root, source, before) {
            resolving.push(name.to_owned());
            let evidence = binding_flag_evidence(
                initializer,
                root,
                source,
                initializer.start_byte(),
                resolving,
            );
            resolving.pop();
            return evidence;
        }
    }

    let mut evidence = BindingFlagEvidence::default();
    let mut cursor = expression.walk();
    for child in expression
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
    {
        let child = binding_flag_evidence(child, root, source, before, resolving);
        evidence.non_public = evidence.non_public.or(child.non_public);
        evidence.has_scope |= child.has_scope;
    }
    evidence
}

fn variable_initializer<'t>(
    identifier: Node<'t>,
    root: Node<'t>,
    source: &str,
    before: usize,
) -> Option<Node<'t>> {
    let wanted = canonical(node_text(identifier, source));
    let owner = enclosing_callable(identifier).map(|callable| callable.id());
    collect_kinds(root, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.end_byte() <= before)
        .filter(|declarator| enclosing_callable(*declarator).map(|callable| callable.id()) == owner)
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            (canonical(node_text(name, source)) == wanted)
                .then(|| declarator_initializer(declarator, name))
                .flatten()
                .map(|initializer| (declarator.start_byte(), initializer))
        })
        .max_by_key(|(start, _)| *start)
        .map(|(_, initializer)| initializer)
}

fn has_static_binding_flags_import(root: Node<'_>, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .map(|using| {
            node_text(using, source)
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace('@', "")
        })
        .any(|using| {
            using == "usingstaticSystem.Reflection.BindingFlags;"
                || using == "usingstaticBindingFlags;"
        })
}
