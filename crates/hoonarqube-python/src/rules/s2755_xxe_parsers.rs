use crate::engine::file_context::FileContext;
use crate::support::{
    child_bodies, for_each_expr, for_each_stmt_in_scope, is_false_literal, issue_at, keyword_value,
    stmt_exprs, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};

pub(crate) fn check_s2755_xxe_parsers(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut module_bindings = ScopeBindings::default();
    visit_scope(
        file_ctx.module_body,
        &mut module_bindings,
        index,
        source,
        &mut issues,
    );
    issues
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ParserSafety {
    Safe,
    Unsafe,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum XmlIdentity {
    Unknown,
    Lxml,
    LxmlEtree,
    Xml,
    XmlEtree,
    XmlElementTree,
    XmlDom,
    XmlMinidom,
    XmlSax,
    XmlParser,
    ParseFunction,
}

#[derive(Clone, Copy)]
struct Binding {
    identity: XmlIdentity,
    parser_safety: Option<ParserSafety>,
}

impl Binding {
    const UNKNOWN: Self = Self {
        identity: XmlIdentity::Unknown,
        parser_safety: None,
    };
}

#[derive(Clone, Default)]
struct ScopeBindings {
    values: HashMap<String, Binding>,
}

fn visit_scope(
    suite: &[Stmt],
    bindings: &mut ScopeBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for statement in suite {
        for expression in stmt_exprs(statement) {
            for_each_expr(expression, &mut |expression| {
                let Expr::Call(call) = expression else {
                    return;
                };
                process_call(call, bindings, index, source, issues);
            });
        }
        match statement {
            Stmt::FunctionDef(function) => {
                let mut child = child_scope(bindings, &function.body, Some(function));
                visit_scope(&function.body, &mut child, index, source, issues);
            }
            Stmt::ClassDef(class) => {
                let mut child = child_scope(bindings, &class.body, None);
                visit_scope(&class.body, &mut child, index, source, issues);
            }
            _ => {
                for body in child_bodies(statement) {
                    visit_scope(body, bindings, index, source, issues);
                }
            }
        }
        bind_statement(statement, bindings);
    }
}

fn process_call(
    call: &ruff_python_ast::ExprCall,
    bindings: &ScopeBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if let Some(safety) = parser_constructor_safety(call, bindings) {
        if safety == ParserSafety::Unsafe {
            issues.push(issue_at(
                "python:S2755",
                MESSAGE,
                call.range(),
                index,
                source,
            ));
        }
        return;
    }
    if identity_of_expr(&call.func, bindings) != XmlIdentity::ParseFunction {
        return;
    }
    let parser = call
        .arguments
        .args
        .get(1)
        .or_else(|| keyword_value(&call.arguments, "parser"));
    let safety = parser.and_then(|expr| parser_safety_of_expr(expr, bindings));
    if safety.is_none() {
        issues.push(issue_at(
            "python:S2755",
            MESSAGE,
            call.range(),
            index,
            source,
        ));
    }
}

fn child_scope(
    parent: &ScopeBindings,
    suite: &[Stmt],
    function: Option<&StmtFunctionDef>,
) -> ScopeBindings {
    let mut child = parent.clone();
    let mut locals = HashSet::new();
    for_each_stmt_in_scope(suite, &mut |statement| {
        locals.extend(stmt_store_names(statement));
    });
    if let Some(function) = function {
        for parameter in function
            .parameters
            .posonlyargs
            .iter()
            .chain(&function.parameters.args)
            .chain(&function.parameters.kwonlyargs)
        {
            locals.insert(parameter.parameter.name.as_str().to_string());
        }
        if let Some(parameter) = function.parameters.vararg.as_deref() {
            locals.insert(parameter.name.as_str().to_string());
        }
        if let Some(parameter) = function.parameters.kwarg.as_deref() {
            locals.insert(parameter.name.as_str().to_string());
        }
    }
    for local in locals {
        child.values.insert(local, Binding::UNKNOWN);
    }
    child
}

fn bind_statement(statement: &Stmt, bindings: &mut ScopeBindings) {
    match statement {
        Stmt::Import(import) => {
            for alias in &import.names {
                let local = alias.asname.as_deref().map_or_else(
                    || {
                        alias
                            .name
                            .as_str()
                            .split('.')
                            .next()
                            .unwrap_or("")
                            .to_string()
                    },
                    str::to_string,
                );
                bindings.values.insert(
                    local,
                    Binding {
                        identity: plain_import_identity(
                            alias.name.as_str(),
                            alias.asname.is_some(),
                        ),
                        parser_safety: None,
                    },
                );
            }
        }
        Stmt::ImportFrom(import) => {
            let module = import
                .module
                .as_ref()
                .map(ruff_python_ast::Identifier::as_str);
            for alias in &import.names {
                let local = alias
                    .asname
                    .as_deref()
                    .map_or_else(|| alias.name.as_str().to_string(), str::to_string);
                bindings.values.insert(
                    local,
                    Binding {
                        identity: from_import_identity(module, alias.name.as_str()),
                        parser_safety: None,
                    },
                );
            }
        }
        Stmt::Assign(assign) => {
            let value = binding_for_value(&assign.value, bindings);
            for target in &assign.targets {
                bind_target(target, value, bindings);
            }
        }
        Stmt::AnnAssign(assign) => {
            let value = assign
                .value
                .as_deref()
                .map_or(Binding::UNKNOWN, |value| binding_for_value(value, bindings));
            bind_target(&assign.target, value, bindings);
        }
        _ => {
            for name in stmt_store_names(statement) {
                bindings.values.insert(name, Binding::UNKNOWN);
            }
        }
    }
}

fn bind_target(target: &Expr, binding: Binding, bindings: &mut ScopeBindings) {
    if let Expr::Name(name) = target {
        bindings
            .values
            .insert(name.id.as_str().to_string(), binding);
        return;
    }
    let mut names = Vec::new();
    crate::support::collect_target_names(target, &mut names);
    for name in names {
        bindings.values.insert(name, Binding::UNKNOWN);
    }
}

fn binding_for_value(value: &Expr, bindings: &ScopeBindings) -> Binding {
    let Expr::Call(call) = value else {
        return Binding::UNKNOWN;
    };
    parser_constructor_safety(call, bindings).map_or(Binding::UNKNOWN, |safety| Binding {
        identity: XmlIdentity::Unknown,
        parser_safety: Some(safety),
    })
}

fn plain_import_identity(path: &str, aliased: bool) -> XmlIdentity {
    match (path, aliased) {
        ("lxml" | "lxml.etree", false) => XmlIdentity::Lxml,
        ("lxml.etree", true) => XmlIdentity::LxmlEtree,
        (
            "xml"
            | "xml.etree"
            | "xml.etree.ElementTree"
            | "xml.dom"
            | "xml.dom.minidom"
            | "xml.sax",
            false,
        ) => XmlIdentity::Xml,
        ("xml.etree.ElementTree", true) => XmlIdentity::XmlElementTree,
        ("xml.dom.minidom", true) => XmlIdentity::XmlMinidom,
        ("xml.sax", true) => XmlIdentity::XmlSax,
        _ => XmlIdentity::Unknown,
    }
}

fn from_import_identity(module: Option<&str>, name: &str) -> XmlIdentity {
    match (module, name) {
        (Some("lxml"), "etree") => XmlIdentity::LxmlEtree,
        (Some("xml"), "etree") => XmlIdentity::XmlEtree,
        (Some("xml"), "dom") => XmlIdentity::XmlDom,
        (Some("xml"), "sax") => XmlIdentity::XmlSax,
        (Some("xml.etree"), "ElementTree") => XmlIdentity::XmlElementTree,
        (Some("xml.dom"), "minidom") => XmlIdentity::XmlMinidom,
        (Some("lxml.etree" | "xml.etree.ElementTree"), "XMLParser") => XmlIdentity::XmlParser,
        (
            Some("lxml.etree" | "xml.etree.ElementTree" | "xml.dom.minidom" | "xml.sax"),
            "parse" | "parseString" | "fromstring",
        ) => XmlIdentity::ParseFunction,
        _ => XmlIdentity::Unknown,
    }
}

fn identity_of_expr(expr: &Expr, bindings: &ScopeBindings) -> XmlIdentity {
    match expr {
        Expr::Name(name) => bindings
            .values
            .get(name.id.as_str())
            .map_or(XmlIdentity::Unknown, |binding| binding.identity),
        Expr::Attribute(attribute) => {
            let parent = identity_of_expr(attribute.value.as_ref(), bindings);
            match (parent, attribute.attr.as_str()) {
                (XmlIdentity::Lxml, "etree") => XmlIdentity::LxmlEtree,
                (XmlIdentity::Xml, "etree") => XmlIdentity::XmlEtree,
                (XmlIdentity::Xml, "dom") => XmlIdentity::XmlDom,
                (XmlIdentity::Xml, "sax") => XmlIdentity::XmlSax,
                (XmlIdentity::XmlEtree, "ElementTree") => XmlIdentity::XmlElementTree,
                (XmlIdentity::XmlDom, "minidom") => XmlIdentity::XmlMinidom,
                (XmlIdentity::LxmlEtree | XmlIdentity::XmlElementTree, "XMLParser") => {
                    XmlIdentity::XmlParser
                }
                (
                    XmlIdentity::LxmlEtree
                    | XmlIdentity::XmlElementTree
                    | XmlIdentity::XmlMinidom
                    | XmlIdentity::XmlSax,
                    "parse" | "parseString" | "fromstring",
                ) => XmlIdentity::ParseFunction,
                _ => XmlIdentity::Unknown,
            }
        }
        _ => XmlIdentity::Unknown,
    }
}

fn parser_safety_of_expr(expr: &Expr, bindings: &ScopeBindings) -> Option<ParserSafety> {
    match expr {
        Expr::Name(name) => bindings
            .values
            .get(name.id.as_str())
            .and_then(|binding| binding.parser_safety),
        Expr::Call(call) => parser_constructor_safety(call, bindings),
        _ => None,
    }
}

fn parser_constructor_safety(
    call: &ruff_python_ast::ExprCall,
    bindings: &ScopeBindings,
) -> Option<ParserSafety> {
    if identity_of_expr(&call.func, bindings) != XmlIdentity::XmlParser {
        return None;
    }
    Some(
        keyword_value(&call.arguments, "resolve_entities")
            .filter(|value| is_false_literal(value))
            .map_or(ParserSafety::Unsafe, |_| ParserSafety::Safe),
    )
}

// --- python:S2755 — XML parsers vulnerable to XXE -------------------------------

const MESSAGE: &str = "Disable access to external entities in XML parsing.";

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s2755_flags_true_xml_entity_resolution_at_the_constructor() {
        let source = concat!(
            "from lxml import etree\n",
            "\n",
            "parser = etree.XMLParser(resolve_entities=True)\n",
            "tree = etree.parse(\"xxe.xml\", parser)\n",
            "root = tree.getroot()\n"
        );
        let report = scan(source);
        let found = findings(&report, "python:S2755");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Disable access to external entities in XML parsing."
        );
        assert_eq!(
            (
                found[0].range.start.line,
                found[0].range.start.column,
                found[0].range.end.line,
                found[0].range.end.column
            ),
            (3, 9, 3, 47)
        );
    }

    #[test]
    fn s2755_preserves_explicitly_safe_parser_configuration() {
        let source = concat!(
            "from lxml import etree\n",
            "\n",
            "parser = etree.XMLParser(resolve_entities=False, no_network=True)\n",
            "tree = etree.parse(\"xxe.xml\", parser)\n",
            "root = tree.getroot()\n"
        );
        assert!(findings(&scan(source), "python:S2755").is_empty());
        let near_miss = concat!(
            "from lxml import etree\n",
            "\n",
            "def parse_document(path):\n",
            "    parser = etree.XMLParser(resolve_entities=False)\n",
            "    return etree.parse(path, parser)\n"
        );
        assert!(findings(&scan(near_miss), "python:S2755").is_empty());
    }

    #[test]
    fn s2755_preserves_unimported_xml_lookalikes() {
        let source = "etree = object()\nparser = etree.XMLParser(resolve_entities=True)\n";
        assert!(findings(&scan(source), "python:S2755").is_empty());
    }
    #[test]
    fn s2755_tracks_parser_aliases_and_local_rebinding() {
        let aliased = concat!(
            "from xml.etree import ElementTree as ET\n",
            "\n",
            "parser = ET.XMLParser(resolve_entities=True)\n"
        );
        assert_eq!(findings(&scan(aliased), "python:S2755").len(), 1);
        let rebound = concat!(
            "from lxml import etree\n",
            "etree = object()\n",
            "\n",
            "parser = etree.XMLParser(resolve_entities=True)\n"
        );
        assert!(findings(&scan(rebound), "python:S2755").is_empty());
    }
}
