use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::expressions::{
    enclosing_callable, expression_name, first_named_child, operator_of, resolved_identifier_type,
};
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

/// csharpsquid:S2755 — XML resolvers that can reach external entities enable
/// XXE attacks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let aliases = xml_url_resolver_aliases(root, source);
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if canonical(expression_name(left, source).unwrap_or("")) != "XmlResolver"
            || !unsafe_resolver(right, root, source, &aliases, &mut Vec::new())
        {
            continue;
        }

        let configured_parser = if left.kind() == "member_access_expression" {
            first_named_child(left).is_some_and(|receiver| {
                is_xml_parser(receiver, root, source, assignment.start_byte())
            })
        } else {
            enclosing_object_initializer(assignment).is_some_and(|creation| {
                creation.child_by_field_name("type").is_some_and(|ty| {
                    XML_PARSER_TYPES.contains(&simple_name(node_text(ty, source)))
                })
            })
        };
        if configured_parser {
            issues.push(issue(
                language,
                "S2755",
                "Disable access to external entities in XML parsing.",
                range_of(assignment, source),
            ));
        }
    }
    issues
}

const XML_PARSER_TYPES: [&str; 2] = ["XmlDocument", "XmlReaderSettings"];

fn canonical(name: &str) -> &str {
    name.strip_prefix('@').unwrap_or(name)
}

fn enclosing_object_initializer(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| ancestor.kind() == "object_creation_expression")
}

fn is_xml_parser(receiver: Node<'_>, root: Node<'_>, source: &str, before: usize) -> bool {
    if receiver.kind() == "object_creation_expression" {
        return receiver
            .child_by_field_name("type")
            .is_some_and(|ty| XML_PARSER_TYPES.contains(&simple_name(node_text(ty, source))));
    }
    receiver.kind() == "identifier"
        && (resolved_identifier_type(receiver, source)
            .is_some_and(|ty| XML_PARSER_TYPES.contains(&simple_name(ty)))
            || variable_initializer(receiver, root, source, before).is_some_and(|initializer| {
                is_xml_parser(initializer, root, source, initializer.start_byte())
            }))
}

fn unsafe_resolver(
    expression: Node<'_>,
    root: Node<'_>,
    source: &str,
    aliases: &HashSet<String>,
    resolving: &mut Vec<String>,
) -> bool {
    if expression.kind() == "object_creation_expression" {
        return expression.child_by_field_name("type").is_some_and(|ty| {
            let name = canonical(simple_name(node_text(ty, source)));
            name == "XmlUrlResolver" || aliases.contains(name)
        });
    }
    if expression.kind() == "identifier" {
        let name = canonical(node_text(expression, source));
        if resolving.iter().any(|resolved| resolved == name) {
            return false;
        }
        if let Some(initializer) =
            variable_initializer(expression, root, source, expression.start_byte())
        {
            resolving.push(name.to_owned());
            let unsafe_value = unsafe_resolver(initializer, root, source, aliases, resolving);
            resolving.pop();
            return unsafe_value;
        }
        return false;
    }
    if matches!(
        expression.kind(),
        "parenthesized_expression" | "cast_expression"
    ) {
        return expression
            .named_child(expression.named_child_count().saturating_sub(1))
            .is_some_and(|inner| unsafe_resolver(inner, root, source, aliases, resolving));
    }
    false
}

fn xml_url_resolver_aliases(root: Node<'_>, source: &str) -> HashSet<String> {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter_map(|using| {
            let normalized: String = node_text(using, source)
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            let declaration = normalized.strip_prefix("using")?.strip_suffix(';')?;
            let (alias, target) = declaration.split_once('=')?;
            (canonical(simple_name(target)) == "XmlUrlResolver")
                .then(|| canonical(alias).to_owned())
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2755_tracks_aliases_initializers_and_local_resolvers() {
        let report = analyze_default(
            "using R = System.Xml.XmlUrlResolver;\nclass C { void M() {\nvar first = new XmlDocument { XmlResolver = new R() };\nvar resolver = new XmlUrlResolver();\nvar second = new XmlDocument();\nsecond.XmlResolver = resolver;\n} }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2755").len(), 2);
    }

    #[test]
    fn s2755_uses_exact_types_and_parser_receivers() {
        let report = analyze_default(
            "class XmlUrlResolverFactory { }\nclass Other { public object XmlResolver { get; set; } }\nclass C { void M(Other other) {\nvar doc = new XmlDocument();\ndoc.XmlResolver = new XmlUrlResolverFactory();\nother.XmlResolver = new XmlUrlResolver();\n} }\n",
        );
        assert!(with_key(&report, "csharpsquid:S2755").is_empty());
    }
}
