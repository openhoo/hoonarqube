//! Independently derived GitHub `CodeQL` Go quality queries.
//!
//! This module deliberately does not participate in the frozen `SonarQube`
//! analyzer.  It owns only the five `CodeQL` query IDs listed below.  The parser
//! is single-file and syntax-only; whenever a language or type fact cannot be
//! proved from that input, the rule returns no result rather than guessing.

use std::collections::HashSet;

use hoonarqube_ir::{FlowLocation, Issue, IssueFlow, Pos, Range, sort_issues, u32_saturating};
use tree_sitter::{Node, Parser};

const DUPLICATE_CONDITION: &str = "go/duplicate-condition";
const DUPLICATE_SWITCH_CASE: &str = "go/duplicate-switch-case";
const MISTYPED_EXPONENTIATION: &str = "go/mistyped-exponentiation";
const NEGATIVE_LENGTH_CHECK: &str = "go/negative-length-check";
const WHITESPACE_PRECEDENCE: &str = "go/whitespace-contradicts-precedence";

/// Analyze one Go source file with the independently implemented `CodeQL`
/// quality queries.  Unlike the tolerant Sonar entrypoint, malformed syntax
/// is a hard semantic boundary: recovered trees are never queried.
#[must_use]
pub fn analyze_github_quality(source: &str) -> Vec<Issue> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let root = tree.root_node();
    if root.has_error() {
        return Vec::new();
    }

    let facts = SemanticFacts::collect(root, source);
    let mut issues = Vec::new();
    check_duplicate_conditions(root, source, &facts, &mut issues);
    check_duplicate_switch_cases(root, source, &facts, &mut issues);
    check_mistyped_exponentiation(root, source, &facts, &mut issues);
    check_negative_length(root, source, &facts, &mut issues);
    check_whitespace_precedence(root, source, &mut issues);
    sort_issues(&mut issues);
    issues.dedup();
    debug_assert!(
        issues
            .iter()
            .all(|issue| crate::GITHUB_QUALITY_RULE_IDS.contains(&issue.rule_key.as_str()))
    );
    issues
}

#[derive(Debug, Default)]
struct SemanticFacts {
    /// Constant facts are retained with their lexical binding, rather than by
    /// spelling alone.  This prevents a local declaration from changing the
    /// meaning of a reference to a package constant.
    constants: Vec<ConstantFact>,
    type_bindings: Vec<TypeBinding>,
    bindings: Vec<Binding>,
}

#[derive(Debug, Clone)]
struct ConstantFact {
    name: String,
    scope_start: usize,
    scope_end: usize,
    declaration_start: usize,
    value: Option<i128>,
    bit_pattern: bool,
    untyped_integer: bool,
}

#[derive(Debug, Clone)]
struct TypeBinding {
    name: String,
    ty: String,
    scope_start: usize,
    scope_end: usize,
    declaration_start: usize,
}

#[derive(Debug, Clone)]
struct Binding {
    name: String,
    scope_start: usize,
    scope_end: usize,
    declaration_start: usize,
    unsigned: bool,
    untyped_integer: bool,
    shadows_builtin: bool,
}

impl SemanticFacts {
    fn collect(root: Node<'_>, source: &str) -> Self {
        let mut facts = Self::default();
        facts.collect_type_aliases(root, source);

        // A missing value in a const spec repeats the preceding spec's type
        // and expression list.  Process each const declaration as a unit so
        // the repeated expression is never borrowed from an unrelated block.
        walk(root, &mut |node| {
            if node.kind() == "const_declaration" {
                facts.collect_const_declaration(node, root, source);
            }
        });
        walk(root, &mut |node| facts.collect_binding(node, root, source));
        facts
    }

    fn collect_type_aliases(&mut self, root: Node<'_>, source: &str) {
        walk(root, &mut |node| {
            if !matches!(node.kind(), "type_spec" | "type_alias") {
                return;
            }
            let (Some(name), Some(ty)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("type"),
            ) else {
                return;
            };
            let (scope_start, scope_end) = declaration_scope(node, root);
            self.type_bindings.push(TypeBinding {
                name: text(name, source).to_owned(),
                ty: text(ty, source).trim().to_owned(),
                scope_start,
                scope_end,
                declaration_start: visible_after_declaration(scope_start, root, node),
            });
        });
    }

    fn collect_const_declaration(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        let mut previous_values = Vec::new();
        let mut previous_type = None;
        for (iota, spec) in named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "const_spec")
            .enumerate()
        {
            let explicit_values = spec
                .child_by_field_name("value")
                .map(named_children)
                .unwrap_or_default();
            let values = if explicit_values.is_empty() {
                previous_values.clone()
            } else {
                explicit_values
            };
            let declared_type = spec.child_by_field_name("type").or(previous_type);
            self.collect_const_spec(spec, root, source, &values, declared_type, iota as i128);
            if !values.is_empty() {
                previous_values = values;
            }
            previous_type = spec.child_by_field_name("type").or(previous_type);
        }
    }

    fn collect_const_spec(
        &mut self,
        node: Node<'_>,
        root: Node<'_>,
        source: &str,
        values: &[Node<'_>],
        declared_type: Option<Node<'_>>,
        iota: i128,
    ) {
        let names = declaration_names(node, source);
        let (scope_start, scope_end) = declaration_scope(node, root);
        let declaration_start = visible_after_declaration(scope_start, root, node);
        for (index, name) in names.into_iter().enumerate() {
            let Some(value) = values.get(index).copied() else {
                continue;
            };
            let value_is_bit_pattern = literal_is_bit_pattern(text(value, source))
                || (value.kind() == "identifier"
                    && self.constant_bit_pattern(text(value, source), value.start_byte()));
            let number = eval_int_at(value, source, self, &mut HashSet::new(), Some(iota));
            self.constants.push(ConstantFact {
                name,
                scope_start,
                scope_end,
                declaration_start,
                value: number,
                bit_pattern: value_is_bit_pattern,
                untyped_integer: declared_type.is_none() && number.is_some(),
            });
        }
    }

    fn collect_binding(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        match node.kind() {
            "parameter_declaration" | "variadic_parameter_declaration" => {
                self.collect_parameter_binding(node, root, source);
            }
            "var_spec" | "const_spec" => self.collect_declared_binding(node, root, source),
            "short_var_declaration" => self.collect_short_binding(node, root, source),
            "range_clause" => self.collect_range_binding(node, root, source),
            "function_declaration" => self.collect_function_binding(node, root, source),
            "type_spec" => self.collect_type_binding(node, root, source),
            "import_spec" => self.collect_import_binding(node, root, source),
            _ => {}
        }
    }

    fn collect_parameter_binding(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        let Some(ty) = node.child_by_field_name("type") else {
            return;
        };
        let unsigned = type_is_unsigned(text(ty, source), self, node.end_byte());
        let (scope_start, scope_end) = function_body_scope(node, root);
        for name in parameter_names(node, source) {
            self.bindings.push(Binding {
                shadows_builtin: is_predeclared_value(&name),
                name,
                scope_start,
                scope_end,
                declaration_start: node.end_byte(),
                unsigned,
                untyped_integer: false,
            });
        }
    }

    fn collect_declared_binding(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        let declared_type = node
            .child_by_field_name("type")
            .map(|value| text(value, source));
        let declared_unsigned =
            declared_type.is_some_and(|value| type_is_unsigned(value, self, node.end_byte()));
        let values = node
            .child_by_field_name("value")
            .map(named_children)
            .unwrap_or_default();
        let (scope_start, scope_end) = declaration_scope(node, root);
        let declaration_start = visible_after_declaration(scope_start, root, node);
        for (index, name) in declaration_names(node, source).into_iter().enumerate() {
            let inferred_unsigned = values
                .get(index)
                .is_some_and(|value| expr_is_unsigned(*value, source, self));
            let untyped_integer = node.kind() == "const_spec"
                && declared_type.is_none()
                && self.constants.iter().any(|constant| {
                    constant.name == name
                        && constant.scope_start == scope_start
                        && constant.scope_end == scope_end
                        && constant.declaration_start == declaration_start
                        && constant.untyped_integer
                });
            self.bindings.push(Binding {
                shadows_builtin: is_predeclared_value(&name),
                name,
                scope_start,
                scope_end,
                declaration_start,
                unsigned: declared_type.is_some_and(|_| declared_unsigned)
                    || (declared_type.is_none() && inferred_unsigned),
                untyped_integer,
            });
        }
    }

    fn collect_short_binding(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        let (scope_start, scope_end) = declaration_scope(node, root);
        let declaration_start = visible_after_declaration(scope_start, root, node);
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let values = node
            .child_by_field_name("right")
            .map(named_children)
            .unwrap_or_default();
        for (index, name_node) in named_children(left).into_iter().enumerate() {
            if name_node.kind() != "identifier" {
                continue;
            }
            let name = text(name_node, source).to_owned();
            if self.bindings.iter().any(|binding| {
                binding.name == name
                    && binding.scope_start == scope_start
                    && binding.scope_end == scope_end
                    && binding.declaration_start <= name_node.start_byte()
            }) {
                continue;
            }
            let unsigned = values
                .get(index)
                .is_some_and(|value| expr_is_unsigned(*value, source, self));
            self.bindings.push(Binding {
                shadows_builtin: is_predeclared_value(&name),
                name,
                scope_start,
                scope_end,
                declaration_start,
                unsigned,
                untyped_integer: false,
            });
        }
    }

    fn collect_range_binding(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        if !text(node, source).contains(":=") {
            return;
        }
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let (scope_start, scope_end) = declaration_scope(node, root);
        let declaration_start = visible_after_declaration(scope_start, root, node);
        for name_node in named_children(left) {
            if name_node.kind() != "identifier" {
                continue;
            }
            let name = text(name_node, source).to_owned();
            self.bindings.push(Binding {
                shadows_builtin: is_predeclared_value(&name),
                name,
                scope_start,
                scope_end,
                declaration_start,
                unsigned: false,
                untyped_integer: false,
            });
        }
    }

    fn collect_function_binding(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        if let Some(name) = node.child_by_field_name("name") {
            let name = text(name, source).to_owned();
            self.bindings.push(Binding {
                shadows_builtin: is_predeclared_value(&name),
                name,
                scope_start: root.start_byte(),
                scope_end: root.end_byte(),
                declaration_start: root.start_byte(),
                unsigned: false,
                untyped_integer: false,
            });
        }
    }

    fn collect_type_binding(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        if let Some(name) = node.child_by_field_name("name") {
            let name = text(name, source).to_owned();
            let (scope_start, scope_end) = declaration_scope(node, root);
            self.bindings.push(Binding {
                shadows_builtin: is_predeclared_value(&name),
                name,
                scope_start,
                scope_end,
                declaration_start: visible_after_declaration(scope_start, root, node),
                unsigned: false,
                untyped_integer: false,
            });
        }
    }

    fn collect_import_binding(&mut self, node: Node<'_>, root: Node<'_>, source: &str) {
        let Some(path) = node.child_by_field_name("path") else {
            return;
        };
        let path = text(path, source).trim_matches(['"', '`']);
        let name = node
            .child_by_field_name("name")
            .map(|name| text(name, source).to_owned())
            .or_else(|| path.rsplit('/').next().map(str::to_owned));
        let Some(name) = name.filter(|name| name != "_" && name != ".") else {
            return;
        };
        self.bindings.push(Binding {
            shadows_builtin: is_predeclared_value(&name),
            name,
            scope_start: root.start_byte(),
            scope_end: root.end_byte(),
            declaration_start: root.start_byte(),
            unsigned: false,
            untyped_integer: false,
        });
    }

    fn binding_for(&self, name: &str, at: usize) -> Option<&Binding> {
        self.bindings
            .iter()
            .filter(|binding| {
                binding.name == name
                    && binding.scope_start <= at
                    && at <= binding.scope_end
                    && binding.declaration_start <= at
            })
            .min_by_key(|binding| {
                (
                    binding.scope_end.saturating_sub(binding.scope_start),
                    usize::MAX.saturating_sub(binding.scope_start),
                    usize::MAX.saturating_sub(binding.declaration_start),
                )
            })
    }

    fn constant_for(&self, name: &str, at: usize) -> Option<&ConstantFact> {
        let binding = self.binding_for(name, at);
        self.constants
            .iter()
            .filter(|constant| {
                constant.name == name
                    && constant.scope_start <= at
                    && at <= constant.scope_end
                    && constant.declaration_start <= at
                    && constant.value.is_some()
                    && binding.is_none_or(|binding| {
                        binding.declaration_start == constant.declaration_start
                            && binding.scope_start == constant.scope_start
                            && binding.scope_end == constant.scope_end
                    })
            })
            .min_by_key(|constant| {
                (
                    constant.scope_end.saturating_sub(constant.scope_start),
                    usize::MAX.saturating_sub(constant.scope_start),
                    usize::MAX.saturating_sub(constant.declaration_start),
                )
            })
    }

    fn constant_bit_pattern(&self, name: &str, at: usize) -> bool {
        self.constant_for(name, at)
            .is_some_and(|constant| constant.bit_pattern)
    }

    fn is_shadowed(&self, name: &str, at: usize) -> bool {
        self.binding_for(name, at)
            .is_some_and(|binding| binding.shadows_builtin)
    }

    fn unsigned_binding(&self, name: &str, at: usize) -> Option<bool> {
        self.binding_for(name, at).map(|binding| binding.unsigned)
    }

    fn untyped_integer_binding(&self, name: &str, at: usize) -> bool {
        self.binding_for(name, at)
            .is_some_and(|binding| binding.untyped_integer)
    }

    fn binding_key(&self, name: &str, at: usize) -> String {
        self.binding_for(name, at).map_or_else(
            || format!("unresolved:{name}"),
            |binding| format!("binding:{}:{name}", binding.declaration_start),
        )
    }

    fn type_binding_for(&self, name: &str, at: usize) -> Option<&TypeBinding> {
        self.type_bindings
            .iter()
            .filter(|binding| {
                binding.name == name
                    && binding.scope_start <= at
                    && at <= binding.scope_end
                    && binding.declaration_start <= at
            })
            .min_by_key(|binding| {
                (
                    binding.scope_end.saturating_sub(binding.scope_start),
                    usize::MAX.saturating_sub(binding.scope_start),
                    usize::MAX.saturating_sub(binding.declaration_start),
                )
            })
    }
}

fn is_predeclared_value(name: &str) -> bool {
    matches!(
        name,
        "len" | "cap" | "uint" | "uint8" | "uint16" | "uint32" | "uint64" | "uintptr" | "byte"
    )
}

fn visible_after_declaration(scope_start: usize, root: Node<'_>, node: Node<'_>) -> usize {
    if scope_start == root.start_byte() {
        root.start_byte()
    } else {
        node.end_byte()
    }
}

fn check_duplicate_conditions(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "if_statement" {
            return;
        }
        if node
            .parent()
            .and_then(|parent| parent.child_by_field_name("alternative"))
            .is_some_and(|alternative| alternative.id() == node.id())
        {
            return;
        }
        let mut conditions = Vec::new();
        let mut current = Some(node);
        while let Some(if_node) = current {
            if if_node.child_by_field_name("initializer").is_some() && if_node.id() != node.id() {
                break;
            }
            let Some(condition) = if_node.child_by_field_name("condition") else {
                break;
            };
            conditions.push(condition);
            current = if_node
                .child_by_field_name("alternative")
                .filter(|alternative| alternative.kind() == "if_statement");
        }
        let keys: Vec<_> = conditions
            .iter()
            .map(|condition| expression_key(*condition, source, facts))
            .collect();
        for (index, (condition, key)) in conditions.iter().zip(keys.iter()).enumerate() {
            let Some(key) = key else {
                continue;
            };
            for (earlier, old) in conditions.iter().zip(keys.iter()).take(index) {
                if old.as_ref().is_some_and(|old| old == key) {
                    let mut issue = Issue::new(
                        DUPLICATE_CONDITION,
                        "This condition is a duplicate of an $@.",
                        node_range(*condition, source),
                    );
                    issue.flows.push(IssueFlow {
                        locations: vec![FlowLocation::in_primary_file(
                            "earlier condition",
                            node_range(*earlier, source),
                        )],
                    });
                    issues.push(issue);
                }
            }
        }
    });
}

fn check_duplicate_switch_cases(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |switch| {
        if !matches!(
            switch.kind(),
            "expression_switch_statement" | "type_switch_statement"
        ) {
            return;
        }
        let cases: Vec<Node<'_>> = named_children(switch)
            .into_iter()
            .filter(|node| {
                (switch.kind() == "expression_switch_statement" && node.kind() == "expression_case")
                    || (switch.kind() == "type_switch_statement" && node.kind() == "type_case")
            })
            .collect();
        let mut prior = Vec::<(String, Node<'_>)>::new();
        for case in cases {
            let Some(label) = switch_case_label(case) else {
                continue;
            };
            let Some(key) = expression_key(label, source, facts) else {
                continue;
            };
            for (_, earlier) in prior.iter().filter(|(old, _)| *old == key) {
                let mut issue = Issue::new(
                    DUPLICATE_SWITCH_CASE,
                    "This case is a duplicate of an $@.",
                    node_range(label, source),
                );
                issue.flows.push(IssueFlow {
                    locations: vec![FlowLocation::in_primary_file(
                        "earlier case",
                        node_range(*earlier, source),
                    )],
                });
                issues.push(issue);
            }
            prior.push((key, label));
        }
    });
}

fn switch_case_label(case: Node<'_>) -> Option<Node<'_>> {
    match case.kind() {
        "expression_case" => case
            .child_by_field_name("value")
            .and_then(|values| values.named_child(0)),
        _ => None,
    }
}

fn compact_trivia(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn check_mistyped_exponentiation(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "binary_expression"
            || node
                .child_by_field_name("operator")
                .is_none_or(|operator| text(operator, source) != "^")
        {
            return;
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        let Some(left_value) = eval_int(left, source, facts, &mut HashSet::new()) else {
            return;
        };
        if maybe_xor_bit_pattern(left, left_value, source, facts) {
            return;
        }
        let rhs_is_exponent_name =
            right.kind() == "identifier" && looks_like_exponent_name(text(right, source));
        let rhs_is_number = eval_int(right, source, facts, &mut HashSet::new())
            .is_some_and(|value| value >= 0 && !maybe_xor_bit_pattern(right, value, source, facts));
        if !rhs_is_exponent_name && !rhs_is_number {
            return;
        }
        if assigned_to_mask(node, source) {
            return;
        }
        issues.push(Issue::new(
            MISTYPED_EXPONENTIATION,
            "This expression uses the bitwise exclusive-or operator when exponentiation was likely meant.",
            node_range(node, source),
        ));
    });
}

fn maybe_xor_bit_pattern(node: Node<'_>, value: i128, source: &str, facts: &SemanticFacts) -> bool {
    if value == 1 {
        return true;
    }
    if value == 0 {
        return false;
    }
    if node.kind() == "identifier" {
        return facts.constant_bit_pattern(text(node, source), node.start_byte());
    }
    literal_is_bit_pattern(text(node, source))
}

fn literal_is_bit_pattern(value: &str) -> bool {
    let literal = value.replace('_', "");
    literal.starts_with("0x")
        || literal.starts_with("0X")
        || literal.starts_with("0o")
        || literal.starts_with("0O")
        || (literal.starts_with('0')
            && literal.len() > 1
            && literal.bytes().all(|byte| byte.is_ascii_digit()))
}

fn looks_like_exponent_name(name: &str) -> bool {
    let name = name.trim_start_matches('_').to_ascii_lowercase();
    matches!(name.as_str(), "exp" | "exponent" | "pow" | "power")
}

fn assigned_to_mask(node: Node<'_>, source: &str) -> bool {
    for ancestor in ancestors(node) {
        if !matches!(
            ancestor.kind(),
            "assignment_statement" | "short_var_declaration"
        ) {
            continue;
        }
        let (Some(left), Some(right)) = (
            ancestor.child_by_field_name("left"),
            ancestor.child_by_field_name("right"),
        ) else {
            continue;
        };
        let left_items = assignment_items(left);
        let right_items = assignment_items(right);
        for (index, rhs) in right_items.iter().enumerate() {
            if rhs.start_byte() > node.start_byte() || node.end_byte() > rhs.end_byte() {
                continue;
            }
            let Some(lhs) = left_items.get(index) else {
                continue;
            };
            let masked = match lhs.kind() {
                "identifier" => text(*lhs, source).to_ascii_lowercase().contains("mask"),
                "selector_expression" => lhs
                    .child_by_field_name("field")
                    .is_some_and(|field| text(field, source).to_ascii_lowercase().contains("mask")),
                _ => false,
            };
            if masked {
                return true;
            }
        }
    }
    false
}

fn assignment_items(node: Node<'_>) -> Vec<Node<'_>> {
    if node.kind() == "expression_list" {
        named_children(node)
    } else {
        vec![node]
    }
}

fn check_negative_length(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "binary_expression" {
            return;
        }
        let Some(operator_node) = node.child_by_field_name("operator") else {
            return;
        };
        let operator = text(operator_node, source);
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };

        let selected = match operator {
            "<" | "<=" => eval_int(right, source, facts, &mut HashSet::new())
                .map(|bound| (left, bound, operator)),
            ">" | ">=" => eval_int(left, source, facts, &mut HashSet::new())
                .map(|bound| (right, bound, operator)),
            "==" | "!=" => eval_int(right, source, facts, &mut HashSet::new())
                .map(|bound| (left, bound, operator))
                .or_else(|| {
                    eval_int(left, source, facts, &mut HashSet::new())
                        .map(|bound| (right, bound, operator))
                }),
            _ => None,
        };
        let Some((operand, bound, relation)) = selected else {
            return;
        };
        let Some(description) = non_negative_description(operand, source, facts) else {
            return;
        };
        let (reports, relation_word) = match relation {
            "<" | ">" => (bound <= 0, "be less than"),
            "<=" | ">=" => (bound < 0, "be less than"),
            "==" | "!=" => (bound < 0, "equal"),
            _ => (false, "be less than"),
        };
        if !reports {
            return;
        }
        issues.push(Issue::new(
            NEGATIVE_LENGTH_CHECK,
            format!(
                "{description} is always non-negative, and hence cannot {relation_word} {bound}."
            ),
            node_range(node, source),
        ));
    });
}

fn non_negative_description(
    node: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
) -> Option<&'static str> {
    if node.kind() == "parenthesized_expression" {
        return node
            .named_child(0)
            .and_then(|inner| non_negative_description(inner, source, facts));
    }
    if node.kind() == "call_expression" {
        let function = node.child_by_field_name("function")?;
        let function = if function.kind() == "parenthesized_expression" {
            function.named_child(0)?
        } else {
            function
        };
        let name = text(function, source);
        if matches!(name, "len" | "cap")
            && function.kind() == "identifier"
            && !facts.is_shadowed(name, node.start_byte())
        {
            return Some(if name == "len" { "'len'" } else { "'cap'" });
        }
    }
    if expr_is_unsigned(node, source, facts) {
        return Some("This unsigned value");
    }
    None
}

fn expr_is_unsigned(node: Node<'_>, source: &str, facts: &SemanticFacts) -> bool {
    match node.kind() {
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|inner| expr_is_unsigned(inner, source, facts)),
        "identifier" => facts
            .unsigned_binding(text(node, source), node.start_byte())
            .unwrap_or(false),
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return false;
            };
            function.kind() == "identifier"
                && is_unsigned_conversion(text(function, source))
                && !facts.is_shadowed(text(function, source), node.start_byte())
        }
        "unary_expression" => {
            let Some(operator) = node.child_by_field_name("operator") else {
                return false;
            };
            matches!(text(operator, source), "+" | "-" | "^")
                && node
                    .child_by_field_name("operand")
                    .is_some_and(|operand| expr_is_unsigned(operand, source, facts))
        }
        "binary_expression" => {
            let Some(operator) = node.child_by_field_name("operator") else {
                return false;
            };
            let Some((left, right)) = node
                .child_by_field_name("left")
                .zip(node.child_by_field_name("right"))
            else {
                return false;
            };
            let operator = text(operator, source);
            if matches!(operator, "<<" | ">>") {
                return expr_is_unsigned(left, source, facts);
            }
            if !matches!(
                operator,
                "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "&^"
            ) {
                return false;
            }
            (expr_is_unsigned(left, source, facts)
                && (expr_is_unsigned(right, source, facts)
                    || untyped_integer(right, source, facts)))
                || (expr_is_unsigned(right, source, facts) && untyped_integer(left, source, facts))
        }
        _ => false,
    }
}

fn is_unsigned_conversion(name: &str) -> bool {
    matches!(
        name,
        "uint" | "uint8" | "uint16" | "uint32" | "uint64" | "uintptr" | "byte"
    )
}

fn untyped_integer(node: Node<'_>, source: &str, facts: &SemanticFacts) -> bool {
    match node.kind() {
        "int_literal" => true,
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|inner| untyped_integer(inner, source, facts)),
        "identifier" => facts.untyped_integer_binding(text(node, source), node.start_byte()),
        "unary_expression" => {
            node.child_by_field_name("operator")
                .is_some_and(|operator| matches!(text(operator, source), "+" | "-"))
                && node
                    .child_by_field_name("operand")
                    .is_some_and(|operand| untyped_integer(operand, source, facts))
        }
        "binary_expression" => {
            node.child_by_field_name("operator")
                .is_some_and(|operator| {
                    matches!(
                        text(operator, source),
                        "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "&^" | "<<" | ">>"
                    )
                })
                && node
                    .child_by_field_name("left")
                    .zip(node.child_by_field_name("right"))
                    .is_some_and(|(left, right)| {
                        untyped_integer(left, source, facts)
                            && untyped_integer(right, source, facts)
                    })
        }
        _ => false,
    }
}
fn check_whitespace_precedence(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |outer| {
        if outer.kind() != "binary_expression" {
            return;
        }
        let Some(outer_op_node) = outer.child_by_field_name("operator") else {
            return;
        };
        let outer_op = text(outer_op_node, source);
        for (index, inner) in [
            outer.child_by_field_name("left"),
            outer.child_by_field_name("right"),
        ]
        .into_iter()
        .enumerate()
        {
            let Some(inner) = inner.filter(|operand| operand.kind() == "binary_expression") else {
                continue;
            };
            let Some(inner_op_node) = inner.child_by_field_name("operator") else {
                continue;
            };
            let inner_op = text(inner_op_node, source);
            if !interesting_nesting(inner_op, outer_op, index) {
                continue;
            }
            let (Some(inner_score), Some(outer_score)) = (
                whitespace_around(inner, source),
                whitespace_around(outer, source),
            ) else {
                continue;
            };
            if inner_score > outer_score {
                issues.push(Issue::new(
                    WHITESPACE_PRECEDENCE,
                    format!(
                        "{inner_op} is evaluated before {outer_op}, but whitespace suggests the opposite."
                    ),
                    node_range(outer, source),
                ));
            }
        }
    });
}

fn interesting_nesting(inner_op: &str, outer_op: &str, index: usize) -> bool {
    let associative = inner_op == outer_op
        && matches!(
            inner_op,
            "+" | "*" | "&" | "|" | "^" | "&^" | "<<" | ">>" | "&&" | "||"
        );
    let reassociated = (inner_op == "*" && outer_op == "/" && index == 0)
        || (inner_op == "/" && outer_op == "%" && index == 0)
        || (inner_op == "+" && outer_op == "-" && index == 0);
    let harmless = (is_comparison(outer_op) && (is_arithmetic(inner_op) || is_shift(inner_op)))
        || (is_logical(outer_op) && is_comparison(inner_op));
    !(associative || reassociated || harmless)
}

fn is_arithmetic(operator: &str) -> bool {
    matches!(operator, "+" | "-" | "*" | "/" | "%")
}

fn is_shift(operator: &str) -> bool {
    matches!(operator, "<<" | ">>")
}

fn is_comparison(operator: &str) -> bool {
    matches!(operator, "==" | "!=" | "<" | "<=" | ">" | ">=")
}

fn is_logical(operator: &str) -> bool {
    matches!(operator, "&&" | "||")
}

fn whitespace_around(node: Node<'_>, source: &str) -> Option<usize> {
    let operator = node.child_by_field_name("operator")?;
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    if left.start_position().row != right.start_position().row {
        return None;
    }
    // Match CodeQL's Location-column formula rather than counting raw
    // characters. This intentionally uses byte columns, as tree-sitter and
    // CodeQL both measure the source locations of these ASCII operators.
    let gap = right
        .start_position()
        .column
        .saturating_sub(left.end_position().column)
        .saturating_sub(operator.end_byte().saturating_sub(operator.start_byte()));
    let _ = source;
    Some(gap / 2)
}

fn expression_key(node: Node<'_>, source: &str, facts: &SemanticFacts) -> Option<String> {
    if let Some(value) = eval_int(node, source, facts, &mut HashSet::new()) {
        return Some(format!("const:{value}"));
    }
    match node.kind() {
        "parenthesized_expression" => node
            .named_child(0)
            .and_then(|inner| expression_key(inner, source, facts)),
        "identifier" => {
            let name = text(node, source);
            if name == "nil" {
                // CodeQL gives each unanalyzable nil expression a distinct
                // global value; spelling alone must not imply equality.
                return None;
            }
            Some(format!("id:{}", facts.binding_key(name, node.start_byte())))
        }
        "field_identifier" => Some(format!("name:{}", text(node, source))),
        "type_identifier"
        | "qualified_type"
        | "pointer_type"
        | "slice_type"
        | "array_type"
        | "map_type"
        | "channel_type"
        | "function_type"
        | "interface_type"
        | "struct_type"
        | "parenthesized_type"
        | "type_instantiation_expression" => {
            Some(format!("type:{}", compact_trivia(text(node, source))))
        }
        "true" | "false" => Some(format!("literal:{}", text(node, source))),
        "nil" => {
            // CodeQL gives each unanalyzable nil expression a distinct
            // global value; spelling alone must not imply equality.
            None
        }
        "interpreted_string_literal" | "raw_string_literal" | "rune_literal" => {
            Some(format!("literal:{}", text(node, source)))
        }
        "selector_expression" => {
            let operand = node.child_by_field_name("operand")?;
            let field = node.child_by_field_name("field")?;
            Some(format!(
                "selector:{}/{}",
                expression_key(operand, source, facts)?,
                text(field, source)
            ))
        }
        "index_expression" => Some(format!(
            "index:{}[{}]",
            expression_key(node.child_by_field_name("operand")?, source, facts)?,
            expression_key(node.child_by_field_name("index")?, source, facts)?
        )),
        "unary_expression" => Some(format!(
            "unary:{}({})",
            text(node.child_by_field_name("operator")?, source),
            expression_key(node.child_by_field_name("operand")?, source, facts)?
        )),
        "binary_expression" => Some(format!(
            "binary:{}({},{})",
            text(node.child_by_field_name("operator")?, source),
            expression_key(node.child_by_field_name("left")?, source, facts)?,
            expression_key(node.child_by_field_name("right")?, source, facts)?
        )),
        _ => None,
    }
}

fn eval_int(
    node: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    seen: &mut HashSet<String>,
) -> Option<i128> {
    eval_int_at(node, source, facts, seen, None)
}

fn eval_int_at(
    node: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    seen: &mut HashSet<String>,
    iota: Option<i128>,
) -> Option<i128> {
    match node.kind() {
        "int_literal" => parse_integer(text(node, source)).and_then(codeql_int),
        "parenthesized_expression" => node
            .named_child(0)
            .and_then(|inner| eval_int_at(inner, source, facts, seen, iota)),
        "identifier" => {
            let name = text(node, source);
            if name == "iota" {
                return iota.and_then(codeql_int);
            }
            let key = facts.binding_key(name, node.start_byte());
            if !seen.insert(key.clone()) {
                return None;
            }
            let value = facts
                .constant_for(name, node.start_byte())
                .and_then(|constant| constant.value);
            seen.remove(&key);
            value
        }
        "unary_expression" => {
            let operator = text(node.child_by_field_name("operator")?, source);
            let operand = node.child_by_field_name("operand")?;
            if operator == "-"
                && let Some(value) = parse_integer(text(operand, source))
                && value == i128::from(i32::MAX) + 1
            {
                return Some(i128::from(i32::MIN));
            }
            let value = eval_int_at(operand, source, facts, seen, iota)?;
            match operator {
                "+" => codeql_int(value),
                "-" => value.checked_neg().and_then(codeql_int),
                _ => None,
            }
        }
        "binary_expression" => {
            let operator = text(node.child_by_field_name("operator")?, source);
            let left = eval_int_at(node.child_by_field_name("left")?, source, facts, seen, iota)?;
            let right = eval_int_at(
                node.child_by_field_name("right")?,
                source,
                facts,
                seen,
                iota,
            )?;
            let value = match operator {
                "+" => left.checked_add(right),
                "-" => left.checked_sub(right),
                "*" => left.checked_mul(right),
                "/" if right != 0 => left.checked_div(right),
                "%" if right != 0 => left.checked_rem(right),
                "<<" => u32::try_from(right)
                    .ok()
                    .and_then(|shift| left.checked_shl(shift)),
                ">>" => u32::try_from(right)
                    .ok()
                    .and_then(|shift| left.checked_shr(shift)),
                "&" => Some(left & right),
                "|" => Some(left | right),
                "^" => Some(left ^ right),
                "&^" => Some(left & !right),
                _ => None,
            }?;
            codeql_int(value)
        }
        _ => None,
    }
}

fn codeql_int(value: i128) -> Option<i128> {
    (i128::from(i32::MIN)..=i128::from(i32::MAX))
        .contains(&value)
        .then_some(value)
}

fn parse_integer(value: &str) -> Option<i128> {
    let value = value.replace('_', "");
    let (digits, radix) = if value.starts_with("0x") || value.starts_with("0X") {
        (&value[2..], 16)
    } else if value.starts_with("0o") || value.starts_with("0O") {
        (&value[2..], 8)
    } else if value.starts_with("0b") || value.starts_with("0B") {
        (&value[2..], 2)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value.as_str(), 10)
    };
    i128::from_str_radix(digits, radix).ok()
}

fn type_is_unsigned(ty: &str, facts: &SemanticFacts, at: usize) -> bool {
    let mut current = ty.trim().to_owned();
    let mut seen = HashSet::new();
    loop {
        if current.starts_with('*') || current.contains('[') || current.contains('.') {
            return false;
        }
        if !seen.insert(current.clone()) {
            return false;
        }
        if let Some(binding) = facts.type_binding_for(&current, at) {
            current = binding.ty.clone();
            continue;
        }
        return matches!(
            current.as_str(),
            "uint" | "uint8" | "uint16" | "uint32" | "uint64" | "uintptr" | "byte"
        );
    }
}

fn parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let type_start = node
        .child_by_field_name("type")
        .map_or(node.end_byte(), |child| child.start_byte());
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "identifier" && child.start_byte() < type_start)
        .map(|child| text(child, source).to_owned())
        .collect()
}

fn declaration_names(node: Node<'_>, source: &str) -> Vec<String> {
    let boundary = node
        .child_by_field_name("type")
        .or_else(|| node.child_by_field_name("value"))
        .map_or(node.end_byte(), |child| child.start_byte());
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "identifier" && child.start_byte() < boundary)
        .map(|child| text(child, source).to_owned())
        .collect()
}

fn function_body_scope(node: Node<'_>, root: Node<'_>) -> (usize, usize) {
    ancestors(node)
        .find_map(|ancestor| {
            ancestor
                .child_by_field_name("body")
                .filter(|body| body.kind() == "block")
                .map(|body| (body.start_byte(), body.end_byte()))
        })
        .unwrap_or((root.start_byte(), root.end_byte()))
}

fn declaration_scope(node: Node<'_>, root: Node<'_>) -> (usize, usize) {
    for ancestor in ancestors(node) {
        match ancestor.kind() {
            "block" => {
                return (ancestor.start_byte(), ancestor.end_byte());
            }
            "if_statement"
            | "for_statement"
            | "expression_switch_statement"
            | "type_switch_statement"
                if node.kind() == "short_var_declaration" || node.kind() == "range_clause" =>
            {
                return (ancestor.start_byte(), ancestor.end_byte());
            }
            _ => {}
        }
    }
    (root.start_byte(), root.end_byte())
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .collect()
}

fn walk<'tree>(node: Node<'tree>, callback: &mut impl FnMut(Node<'tree>)) {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        callback(current);
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                pending.push(child);
            }
        }
    }
}

fn ancestors(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    std::iter::successors(node.parent(), Node::parent)
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or_default()
}

fn node_range(node: Node<'_>, source: &str) -> Range {
    Range {
        start: position_at(source, node.start_byte()),
        end: position_at(source, node.end_byte()),
    }
}

fn position_at(source: &str, byte: usize) -> Pos {
    let byte = byte.min(source.len());
    let before = &source[..byte];
    let line = u32_saturating(before.bytes().filter(|byte| *byte == b'\n').count()) + 1;
    let column = u32_saturating(
        before
            .rsplit('\n')
            .next()
            .map_or(0, |line| line.chars().count()),
    );
    Pos { line, column }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(source: &str) -> Vec<String> {
        analyze_github_quality(source)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect()
    }

    #[test]
    fn duplicate_condition_uses_constant_and_parenthesis_facts() {
        let source = r"package p
func f(x int) {
    if x == 1 {} else if (x == 1) {}
}
";
        assert_eq!(keys(source), vec![DUPLICATE_CONDITION]);
        assert!(keys("package p\nfunc f(x int) { if x == 1 {} else if x == 2 {} }\n").is_empty());
    }

    #[test]
    fn duplicate_switch_uses_only_the_first_label_for_gvn() {
        let source = r"package p
func f(x int) {
    switch x {
    case 1, 2:
    case 1, 3:
    }
}
";
        assert_eq!(keys(source), vec![DUPLICATE_SWITCH_CASE]);
        let non_duplicate = "package p\nfunc f(x int) { switch x { case 1, 2: case 2, 3: } }\n";
        assert!(keys(non_duplicate).is_empty());
        assert!(
            keys("package p\nfunc f(x int) { switch x { case 1, 2: case 3, 4: } }\n").is_empty()
        );
    }

    #[test]
    fn mistyped_exponentiation_respects_constants_and_masks() {
        let source = r"package p
func f() {
    _ = 2 ^ 32
    mask := 2 ^ 32
    _ = mask
    _ = 0x10 ^ 32
}
";
        assert_eq!(keys(source), vec![MISTYPED_EXPONENTIATION]);
    }

    #[test]
    fn negative_length_checks_official_operator_boundaries() {
        let source = r"package p
func f(xs []int, u uint) {
    if len(xs) < 0 {}
    if u == -1 {}
    if len(xs) <= -1 {}
    if len(xs) != -1 {}
    if 0 > len(xs) {}
    if 0 >= len(xs) {}
    if len(xs) == 0 {}
}
";
        assert_eq!(keys(source).len(), 5);
        let shadowed = "package p\nfunc f(len func([]int) int, xs []int) { if len(xs) < 0 {} }\n";
        assert!(keys(shadowed).is_empty());
    }

    #[test]
    fn whitespace_precedence_uses_actual_operator_gaps() {
        let source = r"package p
func f(x int, pos uint) bool {
    return x & 1<<pos != 0
}
";
        assert_eq!(keys(source), vec![WHITESPACE_PRECEDENCE]);
        assert!(keys("package p\nfunc f(x int) int { return x + x>>1 }\n").is_empty());
        assert!(keys("package p\nfunc f(x int) int { return x + (x>>1) }\n").is_empty());
    }

    #[test]
    fn lexical_facts_and_shadowed_conversions_follow_scopes() {
        let source = r"package p
const x = 1
func f(value uint) {
    if x == 1 {} else if x == 1 {}
    {
        x := value
        if x == 1 {} else if 1 == 1 {}
    }
    for len := 0; len < 1; len++ {}
    if len([]int{}) < 0 {}
    u := uint(0)
    if u < 0 {}
}
func g(uint func(int) int) {
    if uint(1) < 0 {}
}
";
        let found = keys(source);
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == DUPLICATE_CONDITION)
                .count(),
            1
        );
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == NEGATIVE_LENGTH_CHECK)
                .count(),
            2
        );
    }

    #[test]
    fn whitespace_harmless_nested_expressions_are_ignored() {
        let source = r"package p
func f(a, b, c, d bool) bool {
    return a + b == c && c == d
}
";
        assert!(keys(source).is_empty());
    }

    #[test]
    fn malformed_syntax_is_a_semantic_boundary() {
        assert!(analyze_github_quality("package p\nfunc f( {\n").is_empty());
    }

    #[test]
    fn duplicate_reports_have_codeql_pair_cardinality() {
        let source =
            "package p\nfunc f(x int) { if x == 1 {} else if x == 1 {} else if x == 1 {} }\n";
        let issues = analyze_github_quality(source);
        let duplicates: Vec<_> = issues
            .iter()
            .filter(|issue| issue.rule_key == DUPLICATE_CONDITION)
            .collect();
        assert_eq!(duplicates.len(), 3);
        assert!(duplicates.iter().all(|issue| issue.flows.len() == 1));

        let source = "package p\nfunc f(x int) { switch x { case 1: case 1: case 1: } }\n";
        let issues = analyze_github_quality(source);
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.rule_key == DUPLICATE_SWITCH_CASE)
                .count(),
            3
        );
    }

    #[test]
    fn duplicate_switch_type_cases_are_not_equated_as_gvn_values() {
        let source = "package p\nfunc f(x any) { switch x.(type) { case int: case int: case string: case int: } }\n";
        assert!(
            keys(source)
                .into_iter()
                .all(|key| key != DUPLICATE_SWITCH_CASE)
        );
    }

    #[test]
    fn nil_expressions_remain_distinct_unanalyzable_values() {
        let duplicate_condition =
            "package p\nfunc f(x any) { if x == nil {} else if x == nil {} }\n";
        assert!(
            keys(duplicate_condition)
                .into_iter()
                .all(|key| key != DUPLICATE_CONDITION),
            "nil comparisons must not be equated by spelling"
        );

        let duplicate_switch = "package p\nfunc f(x any) { switch x { case nil: case nil: } }\n";
        assert!(
            keys(duplicate_switch)
                .into_iter()
                .all(|key| key != DUPLICATE_SWITCH_CASE),
            "nil cases must remain distinct unanalyzable values"
        );
    }

    #[test]
    fn advanced_scopes_types_control_flow_and_trivia_stay_precise() {
        let source = r"package p
type Unsigned = uint
type Box[T any] struct { Value T }
func f(café Unsigned, ch <-chan int) {
    closure := func() {
        if café < 0 {}
    }
    _ = closure
outer:
    for {
        for {
            select {
            case item := <-ch:
                _ = item
            default:
                break outer
            }
        }
    }
    _ = Box[int]{Value: 1} // generic composite literal
}
";
        let issues = analyze_github_quality(source);
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.rule_key == NEGATIVE_LENGTH_CHECK)
                .count(),
            1,
            "the alias remains unsigned through a closure, while control-flow syntax stays clean"
        );
        assert!(
            issues
                .iter()
                .all(|issue| issue.rule_key != DUPLICATE_CONDITION),
            "labels, select, and generic literals must not create duplicate conditions"
        );

        let duplicate = r"package p
func g(café int) {
    check := func() {
        if café == 1 {
        } else if café == 1 {
        }
    }
}
";
        let issue = analyze_github_quality(duplicate)
            .into_iter()
            .find(|issue| issue.rule_key == DUPLICATE_CONDITION)
            .expect("captured Unicode condition should be detected");
        assert_eq!(issue.range.start.line, 5);
        assert_eq!(issue.flows.len(), 1);

        let near_miss = "package p\nfunc h(x int) { if x == 1 {} else if x != 1 {} }\n";
        assert!(
            analyze_github_quality(near_miss)
                .into_iter()
                .all(|issue| issue.rule_key != DUPLICATE_CONDITION),
            "opposite comparisons are not duplicates"
        );
    }
    #[test]
    fn implicit_constants_and_signed_int_boundaries_are_conservative() {
        let source = r"package p
const (
    first = 1
    second
)
func f(x int, xs []int) {
    if x == first {} else if x == second {}
    if len(xs) < -2147483648 {}
    if len(xs) < 2147483648 {}
    if len(xs) < -2147483649 {}
}
";
        let found = keys(source);
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == DUPLICATE_CONDITION)
                .count(),
            1
        );
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == NEGATIVE_LENGTH_CHECK)
                .count(),
            1
        );
    }

    #[test]
    fn short_declaration_preserves_existing_unsigned_binding() {
        let source = "package p\nfunc f(u uint) { u, err := u, 0; if u < 0 {}; _ = err }\n";
        assert_eq!(
            keys(source)
                .into_iter()
                .filter(|key| key == NEGATIVE_LENGTH_CHECK)
                .count(),
            1
        );
    }

    #[test]
    fn exponent_mask_suppression_matches_tuple_sides() {
        let source =
            "package p\nfunc f(exp int) { mask, value := 0, 2 ^ exp; _ = mask; _ = value }\n";
        assert_eq!(keys(source), vec![MISTYPED_EXPONENTIATION]);
    }

    #[test]
    fn whitespace_precedence_uses_codeql_column_scoring() {
        let source = "package p\nfunc f(x int) int { return x+x  >>  1 }\n";
        assert_eq!(keys(source), vec![WHITESPACE_PRECEDENCE]);
        let comment = "package p\nfunc f(x int) int { return x+x /* padding */ >> 1 }\n";
        assert_eq!(keys(comment), vec![WHITESPACE_PRECEDENCE]);
    }
}
