//! Conservative error-type facts for `SonarGo`'s cognitive-complexity guards.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use crate::{
    GoImports, ancestors, named_children, scope_binds_name, text, unwrap_parenthesized, walk,
};

#[cfg(test)]
#[path = "s3776_file_local_tests.rs"]
mod tests;

#[derive(Clone, Default)]
struct TypeFact {
    error: bool,
    slice_of_errors: bool,
    returns: Vec<bool>,
    receiver: Option<String>,
}

struct Binding {
    available_at: usize,
    fact: TypeFact,
}

pub(crate) struct ErrorGuardFacts {
    bindings: HashMap<usize, HashMap<String, Vec<Binding>>>,
    functions: HashMap<String, Vec<bool>>,
    callable_members: HashMap<(String, String), Vec<bool>>,
    aliases: HashMap<String, TypeFact>,
    standard_second_error: HashMap<&'static str, String>,
    error_type_shadowed: bool,
    project_functions: HashMap<String, Vec<bool>>,
    project_variables: HashMap<String, Vec<bool>>,
}

// Each imported function listed here returns the builtin error in position two.
fn standard_second_error(imports: &GoImports) -> HashMap<&'static str, String> {
    [
        ("regexp", "Compile"),
        ("net/url", "QueryUnescape"),
        ("strconv", "ParseBool"),
        ("os", "Stat"),
    ]
    .into_iter()
    .filter_map(|(path, member)| {
        let alias = imports.alias(path)?;
        (imports
            .aliases
            .values()
            .filter(|other| other.as_str() == alias)
            .count()
            == 1)
            .then(|| (member, alias.to_owned()))
    })
    .collect()
}

impl ErrorGuardFacts {
    pub(crate) fn collect(
        root: Node<'_>,
        source: &str,
        imports: &GoImports,
        project: Option<&crate::project_error_index::PackageErrorFacts>,
    ) -> Self {
        let mut facts = Self {
            bindings: HashMap::new(),
            functions: HashMap::new(),
            callable_members: HashMap::new(),
            aliases: HashMap::new(),
            standard_second_error: standard_second_error(imports),
            error_type_shadowed: false,
            project_functions: project.map_or_else(HashMap::new, |p| {
                p.functions
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }),
            project_variables: project.map_or_else(HashMap::new, |p| {
                p.variables
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }),
        };
        // File imports retain their own scope; aliases are never pooled.
        facts
            .project_functions
            .retain(|name, _| !imports.aliases.values().any(|alias| alias == name));
        facts
            .project_variables
            .retain(|name, _| !imports.aliases.values().any(|alias| alias == name));
        let mut declarations = Vec::new();
        let mut shadowed_aliases = HashSet::new();
        walk(root, &mut |node| {
            if matches!(node.kind(), "type_spec" | "type_alias") {
                facts.collect_type_declaration(node, source, &mut shadowed_aliases);
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
            if node.kind() == "method_declaration"
                && let Some(name) = node.child_by_field_name("name")
                && let Some(receiver) = node
                    .child_by_field_name("receiver")
                    .and_then(crate::first_named)
                    .and_then(|parameter| parameter.child_by_field_name("type"))
                    .and_then(|kind| Self::receiver_name(kind, source))
            {
                facts
                    .callable_members
                    .entry((receiver.to_owned(), text(name, source).to_owned()))
                    .and_modify(Vec::clear)
                    .or_insert_with(|| Self::function_type(node, source).returns);
            }
            if matches!(
                node.kind(),
                "parameter_declaration"
                    | "variadic_parameter_declaration"
                    | "var_spec"
                    | "short_var_declaration"
                    | "range_clause"
                    | "default_case"
            ) {
                declarations.push(node);
            }
        });
        facts
            .aliases
            .retain(|name, _| !shadowed_aliases.contains(name));
        facts
            .callable_members
            .retain(|(receiver, _), _| !shadowed_aliases.contains(receiver));
        declarations.sort_by_key(Node::start_byte);
        for declaration in declarations {
            match declaration.kind() {
                "range_clause" => facts.collect_range_value(declaration, source),
                "default_case" => facts.collect_default_alias(declaration, source),
                _ => facts.collect_binding(declaration, source),
            }
        }
        facts
    }

    fn collect_type_declaration(
        &mut self,
        node: Node<'_>,
        source: &str,
        shadowed_aliases: &mut HashSet<String>,
    ) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let name = text(name, source);
        self.error_type_shadowed |= name == "error";
        if ancestors(node).any(crate::is_function) {
            shadowed_aliases.insert(name.to_owned());
            return;
        }
        if node.kind() != "type_spec" {
            return;
        }
        let Some(kind) = node.child_by_field_name("type") else {
            return;
        };
        match kind.kind() {
            "function_type" => {
                self.aliases
                    .insert(name.to_owned(), Self::function_type(kind, source));
            }
            "struct_type" if node.child_by_field_name("type_parameters").is_none() => {
                self.collect_struct_callbacks(kind, name, source);
            }
            _ => {}
        }
    }

    fn collect_struct_callbacks(&mut self, kind: Node<'_>, receiver: &str, source: &str) {
        let Some(fields) = named_children(kind)
            .into_iter()
            .find(|n| n.kind() == "field_declaration_list")
        else {
            return;
        };
        // Only direct, explicitly typed fields belong to this receiver.
        for field in named_children(fields) {
            let Some(signature) = field
                .child_by_field_name("type")
                .filter(|n| n.kind() == "function_type")
            else {
                continue;
            };
            let mut cursor = field.walk();
            for name in field.children_by_field_name("name", &mut cursor) {
                self.callable_members
                    .entry((receiver.to_owned(), text(name, source).to_owned()))
                    .and_modify(Vec::clear)
                    .or_insert_with(|| Self::function_type(signature, source).returns);
            }
        }
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
                        .is_some_and(|kind| is_builtin_error(kind, source));
                    let mut cursor = parameter.walk();
                    let count = parameter
                        .children_by_field_name("name", &mut cursor)
                        .count()
                        .max(1);
                    returns.extend(std::iter::repeat_n(error, count));
                }
            } else {
                returns.push(is_builtin_error(result, source));
            }
        }
        TypeFact {
            returns,
            ..TypeFact::default()
        }
    }

    fn declared_type(&self, kind: Node<'_>, source: &str) -> TypeFact {
        if kind.kind() == "function_type" {
            Self::function_type(kind, source)
        } else if kind.kind() == "slice_type" {
            TypeFact {
                slice_of_errors: kind
                    .child_by_field_name("element")
                    .is_some_and(|element| is_builtin_error(element, source)),
                ..TypeFact::default()
            }
        } else if is_builtin_error(kind, source) {
            TypeFact {
                error: true,
                ..TypeFact::default()
            }
        } else {
            self.aliases
                .get(text(kind, source))
                .cloned()
                .unwrap_or_else(|| TypeFact {
                    receiver: Self::receiver_name(kind, source)
                        .filter(|name| {
                            self.callable_members
                                .keys()
                                .any(|(receiver, _)| receiver == name)
                        })
                        .map(str::to_owned),
                    ..TypeFact::default()
                })
        }
    }

    fn receiver_name<'source>(kind: Node<'_>, source: &'source str) -> Option<&'source str> {
        let kind = if kind.kind() == "pointer_type" {
            crate::first_named(kind)?
        } else {
            kind
        };
        (kind.kind() == "type_identifier").then(|| text(kind, source))
    }

    fn collect_binding(&mut self, node: Node<'_>, source: &str) {
        let variadic = node.kind() == "variadic_parameter_declaration";
        let parameter = node.kind() == "parameter_declaration" || variadic;
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
                        | "type_switch_statement"
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
        let declared = node.child_by_field_name("type").map(|kind| {
            if variadic {
                TypeFact {
                    slice_of_errors: is_builtin_error(kind, source),
                    ..TypeFact::default()
                }
            } else {
                self.declared_type(kind, source)
            }
        });
        for (index, name) in names.iter().enumerate() {
            let mut fact = declared.clone().unwrap_or_else(|| {
                if values.len() == names.len() {
                    self.expression_type(values[index], 0, source)
                } else if values.len() == 1 {
                    self.expression_type(values[0], index, source)
                } else {
                    TypeFact::default()
                }
            });
            if scope.kind() == "source_file"
                && let Some(returns) = self.project_variables.get(text(*name, source))
            {
                fact.returns.clone_from(returns);
            }
            let available_at = if parameter || scope.kind() == "source_file" {
                0
            } else {
                node.end_byte()
            };
            self.bind(scope, text(*name, source), available_at, fact);
        }
    }

    fn bind(&mut self, scope: Node<'_>, name: &str, available_at: usize, fact: TypeFact) {
        self.bindings
            .entry(scope.id())
            .or_default()
            .entry(name.to_owned())
            .or_default()
            .push(Binding { available_at, fact });
    }

    fn collect_range_value(&mut self, clause: Node<'_>, source: &str) {
        if !crate::has_direct_child(clause, ":=") {
            return;
        }
        let Some(value) = clause
            .child_by_field_name("left")
            .map(named_children)
            .and_then(|names| {
                let mut ids = names.into_iter().filter(|n| n.kind() != "comment");
                let (_, value) = (ids.next()?, ids.next()?);
                (ids.next().is_none() && value.kind() == "identifier").then_some(value)
            })
        else {
            return;
        };
        let Some(collection) = clause
            .child_by_field_name("right")
            .map(unwrap_parenthesized)
            .filter(|n| n.kind() == "identifier")
        else {
            return;
        };
        if let Some(scope) = clause.parent()
            && self
                .lookup(collection, text(collection, source), source)
                .is_some_and(|fact| fact.slice_of_errors)
        {
            self.bind(
                scope,
                text(value, source),
                clause.end_byte(),
                TypeFact {
                    error: true,
                    ..TypeFact::default()
                },
            );
        }
    }

    fn collect_default_alias(&mut self, case: Node<'_>, source: &str) {
        let Some(switch) = case
            .parent()
            .filter(|p| p.kind() == "type_switch_statement")
        else {
            return;
        };
        let Some(alias) = switch.child_by_field_name("alias").and_then(|list| {
            named_children(list)
                .into_iter()
                .find(|n| n.kind() == "identifier")
        }) else {
            return;
        };
        let Some(value) = switch
            .child_by_field_name("value")
            .map(unwrap_parenthesized)
            .filter(|n| n.kind() == "identifier")
        else {
            return;
        };
        // A single concrete type case narrows the alias. The default keeps the
        // static type of the expression evaluated before the alias is in scope.
        if self
            .lookup(value, text(value, source), source)
            .is_some_and(|fact| fact.error)
        {
            self.bind(
                case,
                text(alias, source),
                case.start_byte(),
                TypeFact {
                    error: true,
                    ..TypeFact::default()
                },
            );
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
        if node.kind() == "type_assertion_expression"
            && index == 0
            && let Some(kind) = node.child_by_field_name("type")
        {
            return TypeFact {
                receiver: self.declared_type(kind, source).receiver,
                ..TypeFact::default()
            };
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
                        .then(|| {
                            self.functions.get(name).or_else(|| {
                                (!project_type_is_locally_bound(function, name, source))
                                    .then(|| {
                                        self.project_functions
                                            .get(name)
                                            .or_else(|| self.project_variables.get(name))
                                    })
                                    .flatten()
                            })
                        })
                        .flatten()
                });
            returns
                .and_then(|returns| returns.get(index))
                .copied()
                .unwrap_or(false)
        } else if function.kind() == "selector_expression" {
            self.selector_returns_error(function, index, source)
        } else {
            false
        };
        TypeFact {
            error,
            ..TypeFact::default()
        }
    }

    fn selector_returns_error(&self, function: Node<'_>, index: usize, source: &str) -> bool {
        let Some((receiver, method)) = crate::selector_parts(function, source) else {
            return false;
        };
        if index == 1
            && self
                .standard_second_error
                .get(method)
                .is_some_and(|alias| alias == receiver)
            && !crate::identifier_is_locally_bound(function, receiver, source)
        {
            return true;
        }
        let Some(operand) = function
            .child_by_field_name("operand")
            .map(unwrap_parenthesized)
            .filter(|operand| operand.kind() == "identifier")
        else {
            return false;
        };
        self.lookup(operand, text(operand, source), source)
            .and_then(|fact| fact.receiver.as_ref())
            .and_then(|receiver| {
                self.callable_members
                    .get(&(receiver.clone(), method.to_owned()))
            })
            .and_then(|returns| returns.get(index))
            .copied()
            .unwrap_or(false)
    }
}

/// A generic declaration or a method receiver can reuse the predeclared type name.
fn is_builtin_error(kind: Node<'_>, source: &str) -> bool {
    kind.kind() == "type_identifier"
        && text(kind, source) == "error"
        && !ancestors(kind).any(|owner| declares_error_parameter(owner, source))
}

fn declares_error_parameter(owner: Node<'_>, source: &str) -> bool {
    if let Some(params) = owner.child_by_field_name("type_parameters") {
        return named_children(params).into_iter().any(|p| {
            let mut cursor = p.walk();
            p.children_by_field_name("name", &mut cursor)
                .any(|n| text(n, source) == "error")
        });
    }
    let Some(receiver) = owner.child_by_field_name("receiver") else {
        return false;
    };
    // In a method receiver, the type arguments declare fresh type parameters.
    let mut shadows = false;
    walk(receiver, &mut |n| {
        shadows |= n.kind() == "type_identifier"
            && text(n, source) == "error"
            && n.parent().is_some_and(|p| p.kind() == "type_elem");
    });
    shadows
}

fn project_type_is_locally_bound(call: Node<'_>, name: &str, source: &str) -> bool {
    ancestors(call)
        .filter(|scope| {
            matches!(
                scope.kind(),
                "block" | "expression_case" | "type_case" | "default_case"
            )
        })
        .any(|scope| {
            let statements = named_children(scope)
                .into_iter()
                .find(|n| n.kind() == "statement_list")
                .map_or_else(|| named_children(scope), named_children);
            statements
                .into_iter()
                .take_while(|n| n.start_byte() < call.start_byte())
                .any(|statement| {
                    if statement.kind() != "type_declaration"
                        || statement.end_byte() > call.start_byte()
                    {
                        return false;
                    }
                    let mut found = false;
                    walk(statement, &mut |node| {
                        found |= matches!(node.kind(), "type_spec" | "type_alias")
                            && node
                                .child_by_field_name("name")
                                .is_some_and(|n| text(n, source) == name);
                    });
                    found
                })
        })
}
