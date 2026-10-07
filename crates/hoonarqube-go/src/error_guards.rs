//! Conservative error-type facts for `SonarGo`'s cognitive-complexity guards.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use crate::{
    GoImports, ancestors, named_children, scope_binds_name, text, unwrap_parenthesized, walk,
};

#[derive(Clone, Default)]
struct TypeFact {
    error: bool,
    returns: Vec<bool>,
}

struct Binding {
    available_at: usize,
    fact: TypeFact,
}

pub(crate) struct ErrorGuardFacts {
    bindings: HashMap<usize, HashMap<String, Vec<Binding>>>,
    functions: HashMap<String, Vec<bool>>,
    aliases: HashMap<String, TypeFact>,
    regexp_alias: Option<String>,
    error_type_shadowed: bool,
}

impl ErrorGuardFacts {
    pub(crate) fn collect(root: Node<'_>, source: &str, imports: &GoImports) -> Self {
        let mut facts = Self {
            bindings: HashMap::new(),
            functions: HashMap::new(),
            aliases: HashMap::new(),
            regexp_alias: imports.alias("regexp").map(str::to_owned),
            error_type_shadowed: false,
        };
        let mut declarations = Vec::new();
        let mut shadowed_aliases = HashSet::new();
        walk(root, &mut |node| {
            if node.kind() == "type_spec"
                && let Some(name) = node.child_by_field_name("name")
            {
                facts.error_type_shadowed |= text(name, source) == "error";
                if ancestors(node).any(crate::is_function) {
                    shadowed_aliases.insert(text(name, source).to_owned());
                }
                if let Some(kind) = node.child_by_field_name("type")
                    && kind.kind() == "function_type"
                    && !ancestors(node).any(crate::is_function)
                {
                    facts.aliases.insert(
                        text(name, source).to_owned(),
                        Self::function_type(kind, source),
                    );
                }
            }
            if node.kind() == "function_declaration"
                && let Some(name) = node.child_by_field_name("name")
            {
                let result = Self::function_type(node, source).returns;
                facts
                    .functions
                    .entry(text(name, source).to_owned())
                    .and_modify(Vec::clear)
                    .or_insert(result);
            }
            if matches!(
                node.kind(),
                "parameter_declaration" | "var_spec" | "short_var_declaration"
            ) {
                declarations.push(node);
            }
        });
        facts
            .aliases
            .retain(|name, _| !shadowed_aliases.contains(name));
        declarations.sort_by_key(Node::start_byte);
        for declaration in declarations {
            facts.collect_binding(declaration, source);
        }
        facts
    }

    pub(crate) fn is_error_guard(&self, node: Node<'_>, source: &str) -> bool {
        if self.error_type_shadowed || node.child_by_field_name("alternative").is_some() {
            return false;
        }
        let Some(condition) = node
            .child_by_field_name("condition")
            .map(unwrap_parenthesized)
        else {
            return false;
        };
        if condition.kind() != "binary_expression"
            || !matches!(crate::operator_text(condition, source), "==" | "!=")
        {
            return false;
        }
        let Some((left, right)) = crate::binary_operands(condition) else {
            return false;
        };
        [(left, right), (right, left)]
            .into_iter()
            .any(|(candidate, nil)| {
                candidate.kind() == "identifier"
                    && nil.kind() == "nil"
                    && self
                        .lookup(candidate, text(candidate, source), source)
                        .is_some_and(|fact| fact.error)
            })
    }

    fn lookup(&self, node: Node<'_>, name: &str, source: &str) -> Option<&TypeFact> {
        for scope in ancestors(node) {
            if let Some(binding) = self
                .bindings
                .get(&scope.id())
                .and_then(|names| names.get(name))
                .and_then(|bindings| {
                    let available = bindings
                        .partition_point(|binding| binding.available_at <= node.start_byte());
                    available
                        .checked_sub(1)
                        .and_then(|index| bindings.get(index))
                })
            {
                return Some(&binding.fact);
            }
            // A binding we cannot resolve still shadows outer facts. In
            // particular, range/receive/type-switch declarations must never
            // accidentally inherit an outer error variable's type.
            if scope_binds_name(scope, node, name, source) {
                return None;
            }
        }
        None
    }

    fn function_type(node: Node<'_>, source: &str) -> TypeFact {
        let mut returns = Vec::new();
        if let Some(result) = node.child_by_field_name("result") {
            if result.kind() == "parameter_list" {
                for parameter in named_children(result) {
                    if parameter.kind() != "parameter_declaration" {
                        continue;
                    }
                    let error = parameter
                        .child_by_field_name("type")
                        .is_some_and(|kind| text(kind, source) == "error");
                    let mut cursor = parameter.walk();
                    let count = parameter
                        .children_by_field_name("name", &mut cursor)
                        .count()
                        .max(1);
                    returns.extend(std::iter::repeat_n(error, count));
                }
            } else {
                returns.push(text(result, source) == "error");
            }
        }
        TypeFact {
            error: false,
            returns,
        }
    }

    fn declared_type(&self, kind: Node<'_>, source: &str) -> TypeFact {
        if kind.kind() == "function_type" {
            Self::function_type(kind, source)
        } else if text(kind, source) == "error" {
            TypeFact {
                error: true,
                returns: Vec::new(),
            }
        } else {
            self.aliases
                .get(text(kind, source))
                .cloned()
                .unwrap_or_default()
        }
    }

    fn collect_binding(&mut self, node: Node<'_>, source: &str) {
        let parameter = node.kind() == "parameter_declaration";
        let scope = if parameter {
            let Some(owner) = node
                .parent()
                .and_then(|list| list.parent())
                .filter(|owner| crate::is_function(*owner))
            else {
                return;
            };
            owner
        } else {
            let Some(scope) = ancestors(node).find(|scope| {
                matches!(
                    scope.kind(),
                    "block"
                        | "if_statement"
                        | "for_statement"
                        | "expression_switch_statement"
                        | "expression_case"
                        | "type_case"
                        | "default_case"
                        | "source_file"
                )
            }) else {
                return;
            };
            scope
        };
        let mut cursor = node.walk();
        let names = if node.kind() == "short_var_declaration" {
            node.child_by_field_name("left")
                .map(named_children)
                .unwrap_or_default()
        } else {
            node.children_by_field_name("name", &mut cursor).collect()
        };
        let values = node
            .child_by_field_name(if node.kind() == "short_var_declaration" {
                "right"
            } else {
                "value"
            })
            .map(named_children)
            .unwrap_or_default();
        let declared = node
            .child_by_field_name("type")
            .map(|kind| self.declared_type(kind, source));
        for (index, name) in names.iter().enumerate() {
            let fact = declared.clone().unwrap_or_else(|| {
                if values.len() == names.len() {
                    self.expression_type(values[index], 0, source)
                } else if values.len() == 1 {
                    self.expression_type(values[0], index, source)
                } else {
                    TypeFact::default()
                }
            });
            self.bindings
                .entry(scope.id())
                .or_default()
                .entry(text(*name, source).to_owned())
                .or_default()
                .push(Binding {
                    available_at: if parameter || scope.kind() == "source_file" {
                        0
                    } else {
                        node.end_byte()
                    },
                    fact,
                });
        }
    }

    fn expression_type(&self, node: Node<'_>, index: usize, source: &str) -> TypeFact {
        let node = unwrap_parenthesized(node);
        if node.kind() == "identifier" && index == 0 {
            return self
                .lookup(node, text(node, source), source)
                .cloned()
                .unwrap_or_default();
        }
        let Some(function) = node
            .child_by_field_name("function")
            .map(unwrap_parenthesized)
        else {
            return TypeFact::default();
        };
        let error = if function.kind() == "identifier" {
            let name = text(function, source);
            let returns = self
                .lookup(function, name, source)
                .map(|fact| &fact.returns)
                .or_else(|| {
                    (!crate::identifier_is_locally_bound(function, name, source))
                        .then(|| self.functions.get(name))
                        .flatten()
                });
            returns
                .and_then(|returns| returns.get(index))
                .copied()
                .unwrap_or(false)
        } else if let Some((receiver, method)) = crate::selector_parts(function, source) {
            index == 1
                && method == "Compile"
                && self.regexp_alias.as_deref() == Some(receiver)
                && !crate::identifier_is_locally_bound(function, receiver, source)
        } else {
            false
        };
        TypeFact {
            error,
            returns: Vec::new(),
        }
    }
}
