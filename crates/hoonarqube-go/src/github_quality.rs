//! Independently derived GitHub `CodeQL` Go quality queries.
//!
//! This module deliberately does not participate in the frozen `SonarQube`
//! analyzer.  It owns only the five `CodeQL` query IDs listed below.  The parser
//! is single-file and syntax-only; whenever a language or type fact cannot be
//! proved from that input, the rule returns no result rather than guessing.

use std::collections::{HashMap, HashSet};

use hoonarqube_ir::{FlowLocation, Issue, IssueFlow, Pos, Range, sort_issues, u32_saturating};
use tree_sitter::{Node, Parser};

const COMPARISON_IDENTICAL: &str = "go/comparison-of-identical-expressions";
const CONSTANT_LENGTH_COMPARISON: &str = "go/constant-length-comparison";
const DUPLICATE_BRANCHES: &str = "go/duplicate-branches";
const DUPLICATE_CONDITION: &str = "go/duplicate-condition";
const DUPLICATE_SWITCH_CASE: &str = "go/duplicate-switch-case";
const IMPOSSIBLE_INTERFACE_NIL_CHECK: &str = "go/impossible-interface-nil-check";
const INCONSISTENT_LOOP_DIRECTION: &str = "go/inconsistent-loop-direction";
const INDEX_OUT_OF_BOUNDS: &str = "go/index-out-of-bounds";
const MISSING_ERROR_CHECK: &str = "go/missing-error-check";
const MISTYPED_EXPONENTIATION: &str = "go/mistyped-exponentiation";
const NEGATIVE_LENGTH_CHECK: &str = "go/negative-length-check";
const REDUNDANT_ASSIGNMENT: &str = "go/redundant-assignment";
const REDUNDANT_OPERATION: &str = "go/redundant-operation";
const REDUNDANT_RECOVER: &str = "go/redundant-recover";
const SHIFT_OUT_OF_RANGE: &str = "go/shift-out-of-range";
const UNEXPECTED_NIL_VALUE: &str = "go/unexpected-nil-value";
const UNHANDLED_WRITABLE_FILE_CLOSE: &str = "go/unhandled-writable-file-close";
const UNREACHABLE_STATEMENT: &str = "go/unreachable-statement";
const USELESS_ASSIGNMENT_TO_FIELD: &str = "go/useless-assignment-to-field";
const USELESS_ASSIGNMENT_TO_LOCAL: &str = "go/useless-assignment-to-local";
const USELESS_EXPRESSION: &str = "go/useless-expression";
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
    analyze_parsed(tree.root_node(), source)
}

pub(crate) fn analyze_parsed(root: Node<'_>, source: &str) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }

    let facts = SemanticFacts::collect(root, source);
    let mut issues = Vec::new();
    check_duplicate_conditions(root, source, &facts, &mut issues);
    check_duplicate_switch_cases(root, source, &facts, &mut issues);
    let imports = crate::GoImports::collect(root, source);
    check_comparison_of_identical_expressions(root, source, &facts, &mut issues);
    check_constant_length_comparison(root, source, &facts, &mut issues);
    check_duplicate_branches(root, source, &mut issues);
    check_impossible_interface_nil_check(root, source, &facts, &mut issues);
    check_inconsistent_loop_direction(root, source, &facts, &mut issues);
    check_index_out_of_bounds(root, source, &facts, &mut issues);
    check_missing_error_check(root, source, &facts, &mut issues);
    check_redundant_assignment(root, source, &facts, &mut issues);
    check_redundant_operation(root, source, &facts, &mut issues);
    check_redundant_recover(root, source, &facts, &mut issues);
    check_shift_out_of_range(root, source, &facts, &mut issues);
    check_unexpected_nil_value(root, source, &facts, &imports, &mut issues);
    check_unhandled_writable_file_close(root, source, &facts, &imports, &mut issues);
    check_unreachable_statements(root, source, &mut issues);
    check_useless_field_assignment(root, source, &facts, &mut issues);
    check_useless_local_assignment(root, source, &facts, &mut issues);
    check_useless_expression(root, source, &mut issues);
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
    let mut lookup_at = at;
    let mut seen = HashSet::new();
    loop {
        if current.starts_with('*') || current.contains('[') || current.contains('.') {
            return false;
        }
        if let Some(binding) = facts.type_binding_for(&current, lookup_at) {
            if !seen.insert((
                binding.name.as_str(),
                binding.scope_start,
                binding.scope_end,
            )) {
                return false;
            }
            // An alias retains the meaning of its target at declaration;
            // shadowing a predeclared type at the use site cannot change it.
            lookup_at = binding.declaration_start;
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

fn strip_parens(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while current.kind() == "parenthesized_expression" {
        let Some(inner) = current.named_child(0) else {
            break;
        };
        current = inner;
    }
    current
}

fn operator_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let operator = node.child_by_field_name("operator")?;
    Some(text(operator, source))
}

fn binary_operands(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    Some((
        node.child_by_field_name("left")?,
        node.child_by_field_name("right")?,
    ))
}

fn single_flow(label: &str, range: Range) -> IssueFlow {
    IssueFlow {
        locations: vec![FlowLocation::in_primary_file(label, range)],
    }
}

fn push_simple(issues: &mut Vec<Issue>, rule: &str, message: impl Into<String>, range: Range) {
    issues.push(Issue::new(rule, message, range));
}

fn is_basic_literal(node: Node<'_>) -> bool {
    matches!(
        strip_parens(node).kind(),
        "int_literal"
            | "float_literal"
            | "imaginary_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "rune_literal"
            | "true"
            | "false"
            | "nil"
    )
}

fn contains_side_effect(node: Node<'_>, source: &str) -> bool {
    let mut found = false;
    walk(node, &mut |inner| {
        found = found
            || match inner.kind() {
                "call_expression" | "type_assertion_expression" => true,
                "unary_expression" => operator_text(inner, source) == Some("<-"),
                _ => false,
            };
    });
    found
}

fn top_level_functions(root: Node<'_>) -> Vec<Node<'_>> {
    let mut functions = Vec::new();
    walk(root, &mut |node| {
        if matches!(node.kind(), "function_declaration" | "method_declaration") {
            functions.push(node);
        }
    });
    functions
}

fn len_call_operand<'a>(node: Node<'a>, source: &str, facts: &SemanticFacts) -> Option<Node<'a>> {
    let stripped = strip_parens(node);
    if stripped.kind() != "call_expression" {
        return None;
    }
    let function = strip_parens(stripped.child_by_field_name("function")?);
    if function.kind() != "identifier" {
        return None;
    }
    let name = text(function, source);
    if !matches!(name, "len" | "cap") || facts.is_shadowed(name, stripped.start_byte()) {
        return None;
    }
    let argument = stripped.child_by_field_name("arguments")?.named_child(0)?;
    (argument.kind() == "identifier").then_some(argument)
}

fn constant_reference(node: Node<'_>, source: &str, facts: &SemanticFacts) -> bool {
    let stripped = strip_parens(node);
    stripped.kind() == "identifier"
        && facts
            .constant_for(text(stripped, source), stripped.start_byte())
            .is_some()
}

fn check_comparison_of_identical_expressions(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    let float_locals = collect_float_names(root, source);
    walk(root, &mut |node| {
        let Some(operator) = operator_text(node, source) else {
            return;
        };
        if node.kind() != "binary_expression" || !is_comparison(operator) {
            return;
        }
        let Some((left, right)) = binary_operands(node) else {
            return;
        };
        let Some(key) = expression_key(left, source, facts) else {
            return;
        };
        if expression_key(right, source, facts).as_ref() != Some(&key) {
            return;
        }
        if identical_comparison_allowed(left, right, source, facts, &float_locals) {
            return;
        }
        let mut issue = Issue::new(
            COMPARISON_IDENTICAL,
            "This expression compares an $@ to itself.",
            node_range(node, source),
        );
        issue
            .flows
            .push(single_flow("expression", node_range(left, source)));
        issues.push(issue);
    });
}

fn collect_float_names(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut floats = HashSet::new();
    walk(root, &mut |node| {
        if !matches!(node.kind(), "var_spec" | "parameter_declaration") {
            return;
        }
        let Some(ty) = node.child_by_field_name("type") else {
            return;
        };
        if !matches!(text(ty, source), "float32" | "float64") {
            return;
        }
        for name in declaration_names(node, source) {
            floats.insert(name);
        }
    });
    floats
}

fn identical_comparison_allowed(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    float_locals: &HashSet<String>,
) -> bool {
    let float_operand = |node: Node<'_>, source: &str| {
        let stripped = strip_parens(node);
        matches!(stripped.kind(), "float_literal" | "imaginary_literal")
            || (stripped.kind() == "identifier" && float_locals.contains(text(stripped, source)))
    };
    float_operand(left, source)
        || float_operand(right, source)
        || (constant_reference(left, source, facts) && is_basic_literal(right))
        || (constant_reference(right, source, facts) && is_basic_literal(left))
}

fn loop_clause(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "for_clause")
}

fn loop_clause_field<'a>(node: Node<'a>, field: &str) -> Option<Node<'a>> {
    loop_clause(node)?.child_by_field_name(field)
}

fn loop_post(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let update = loop_clause_field(node, "update")?;
    let operand = update.named_child(0)?;
    (operand.kind() == "identifier").then_some((update, operand))
}

fn post_incremented_variable(node: Node<'_>, source: &str) -> Option<String> {
    let (post, operand) = loop_post(node)?;
    if post.kind() != "inc_statement" {
        return None;
    }
    Some(text(operand, source).to_owned())
}

fn indexed_by_variable<'a>(
    scope: Node<'a>,
    array: &str,
    index: &str,
    after: usize,
    source: &str,
) -> Option<Node<'a>> {
    let mut found = None;
    walk(scope, &mut |node| {
        if found.is_some() || node.kind() != "index_expression" || node.start_byte() <= after {
            return;
        }
        let (Some(operand), Some(index_node)) = (
            node.child_by_field_name("operand"),
            node.child_by_field_name("index"),
        ) else {
            return;
        };
        let operand = strip_parens(operand);
        let index_node = strip_parens(index_node);
        let matches = operand.kind() == "identifier"
            && text(operand, source) == array
            && index_node.kind() == "identifier"
            && text(index_node, source) == index;
        if matches {
            found = Some(node);
        }
    });
    found
}

fn length_constant_check(
    condition: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
) -> Option<(String, i128)> {
    if condition.kind() != "binary_expression" {
        return None;
    }
    let (left, right) = binary_operands(condition)?;
    let (array, constant) = match operator_text(condition, source)? {
        "!=" => (
            len_call_operand(left, source, facts)?,
            eval_int(right, source, facts, &mut HashSet::new())?,
        ),
        "<=" => (
            len_call_operand(right, source, facts)?,
            eval_int(left, source, facts, &mut HashSet::new())?,
        ),
        _ => return None,
    };
    Some((text(array, source).to_owned(), constant))
}

fn check_constant_length_comparison(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "for_statement" {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let Some(loop_variable) = post_incremented_variable(node, source) else {
            return;
        };
        let Some(guard) = constant_length_guard(body, &loop_variable, source, facts) else {
            return;
        };
        let mut issue = Issue::new(
            CONSTANT_LENGTH_COMPARISON,
            "This checks the length against a constant, but it $@.",
            node_range(guard.condition, source),
        );
        issue.flows.push(single_flow(
            "is indexed using a variable",
            node_range(guard.read, source),
        ));
        issues.push(issue);
    });
}

fn constant_length_guard<'a>(
    body: Node<'a>,
    loop_variable: &str,
    source: &str,
    facts: &SemanticFacts,
) -> Option<LengthGuard<'a>> {
    let mut found = None;
    walk(body, &mut |node| {
        if found.is_some() || node.kind() != "if_statement" {
            return;
        }
        let Some(condition) = node.child_by_field_name("condition") else {
            return;
        };
        let Some((array, _)) = length_constant_check(condition, source, facts) else {
            return;
        };
        let Some(read) =
            indexed_by_variable(body, &array, loop_variable, condition.end_byte(), source)
        else {
            return;
        };
        found = Some(LengthGuard {
            condition,
            read,
            _array: array,
        });
    });
    found
}

struct LengthGuard<'a> {
    condition: Node<'a>,
    read: Node<'a>,
    _array: String,
}

fn check_duplicate_branches(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        if node.kind() != "if_statement" {
            return;
        }
        let (Some(consequent), Some(alternative)) = (
            node.child_by_field_name("consequence"),
            node.child_by_field_name("alternative"),
        ) else {
            return;
        };
        if alternative.kind() != "block"
            || compact_trivia(text(consequent, source)) != compact_trivia(text(alternative, source))
        {
            return;
        }
        let condition = node.child_by_field_name("condition");
        let range =
            condition.map_or_else(|| node_range(node, source), |node| node_range(node, source));
        push_simple(
            issues,
            DUPLICATE_BRANCHES,
            "The 'then' and 'else' branches of this if statement are identical.",
            range,
        );
    });
}

fn loop_update_direction(node: Node<'_>, source: &str) -> Option<(String, &'static str)> {
    let (post, operand) = loop_post(node)?;
    let direction = match post.kind() {
        "inc_statement" => "upward",
        "dec_statement" => "downward",
        _ => return None,
    };
    Some((text(operand, source).to_owned(), direction))
}

fn bounded_direction(condition: Node<'_>, variable: &str, source: &str) -> Option<&'static str> {
    if condition.kind() != "binary_expression" {
        return None;
    }
    let (left, right) = binary_operands(condition)?;
    let left_name = text(left, source);
    let right_name = text(right, source);
    match operator_text(condition, source)? {
        "<" | "<=" if left_name == variable => Some("upward"),
        "<" | "<=" if right_name == variable => Some("downward"),
        ">" | ">=" if left_name == variable => Some("downward"),
        ">" | ">=" if right_name == variable => Some("upward"),
        _ => None,
    }
}

fn check_inconsistent_loop_direction(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "for_statement" {
            return;
        }
        let Some((variable, update)) = loop_update_direction(node, source) else {
            return;
        };
        let Some(condition) = loop_clause_field(node, "condition") else {
            return;
        };
        let Some(bound) = bounded_direction(condition, &variable, source) else {
            return;
        };
        if bound == update {
            return;
        }
        if update == "downward" && expr_is_unsigned_by_name(&variable, condition, facts) {
            return;
        }
        let Some((post, _)) = loop_post(node) else {
            return;
        };
        let mut issue = Issue::new(
            INCONSISTENT_LOOP_DIRECTION,
            format!("This loop counts {update}, but its variable is $@ {bound}."),
            node_range(post, source),
        );
        issue
            .flows
            .push(single_flow("bounded", node_range(condition, source)));
        issues.push(issue);
    });
}

fn expr_is_unsigned_by_name(name: &str, at: Node<'_>, facts: &SemanticFacts) -> bool {
    facts
        .binding_for(name, at.start_byte())
        .is_some_and(|binding| binding.unsigned)
}

fn check_index_out_of_bounds(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        let (condition, body) = match node.kind() {
            "if_statement" => (
                node.child_by_field_name("condition"),
                node.child_by_field_name("consequence"),
            ),
            "for_statement" => (
                loop_clause_field(node, "condition"),
                node.child_by_field_name("body"),
            ),
            _ => (None, None),
        };
        let (Some(condition), Some(body)) = (condition, body) else {
            return;
        };
        if condition.kind() != "binary_expression" || operator_text(condition, source) != Some("<=")
        {
            return;
        }
        let Some((index, array)) = length_index_pair(condition, source, facts) else {
            return;
        };
        let Some(read) = indexed_by_variable(body, &array, &index, condition.end_byte(), source)
        else {
            return;
        };
        if has_unequal_length_guard(root, &index, &array, condition, source, facts) {
            return;
        }
        let mut issue = Issue::new(
            INDEX_OUT_OF_BOUNDS,
            "Off-by-one index comparison against length may lead to out-of-bounds $@.",
            node_range(condition, source),
        );
        issue
            .flows
            .push(single_flow("read", node_range(read, source)));
        issues.push(issue);
    });
}

fn length_index_pair(
    condition: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
) -> Option<(String, String)> {
    let (left, right) = binary_operands(condition)?;
    if let Some(array) = len_call_operand(left, source, facts) {
        return identifier_operand(right, source)
            .map(|index| (index, text(array, source).to_owned()));
    }
    let array = len_call_operand(right, source, facts)?;
    identifier_operand(left, source).map(|index| (index, text(array, source).to_owned()))
}

fn identifier_operand(node: Node<'_>, source: &str) -> Option<String> {
    let stripped = strip_parens(node);
    (stripped.kind() == "identifier").then(|| text(stripped, source).to_owned())
}

fn has_unequal_length_guard(
    root: Node<'_>,
    index: &str,
    array: &str,
    condition: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
) -> bool {
    let mut guarded = false;
    walk(root, &mut |node| {
        if guarded
            || node.end_byte() > condition.start_byte()
            || node.kind() != "binary_expression"
            || operator_text(node, source) != Some("!=")
        {
            return;
        }
        let Some((left, right)) = binary_operands(node) else {
            return;
        };
        let left_is_index =
            strip_parens(left).kind() == "identifier" && text(strip_parens(left), source) == index;
        let right_is_index = strip_parens(right).kind() == "identifier"
            && text(strip_parens(right), source) == index;
        let left_len =
            len_call_operand(left, source, facts).is_some_and(|node| text(node, source) == array);
        let right_len =
            len_call_operand(right, source, facts).is_some_and(|node| text(node, source) == array);
        if (left_is_index && right_len) || (right_is_index && left_len) {
            guarded = true;
        }
    });
    guarded
}

fn check_redundant_assignment(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "assignment_statement" {
            return;
        }
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        if left.named_child_count() != 1 {
            return;
        }
        let Some(target) = left.named_child(0) else {
            return;
        };
        let Some(value) = right.named_child(0) else {
            return;
        };
        if contains_side_effect(left, source) || contains_side_effect(right, source) {
            return;
        }
        let Some(key) = expression_key(target, source, facts) else {
            return;
        };
        if expression_key(value, source, facts).as_ref() != Some(&key) {
            return;
        }
        let mut issue = Issue::new(
            REDUNDANT_ASSIGNMENT,
            "This statement assigns an $@ to itself.",
            node_range(node, source),
        );
        issue
            .flows
            .push(single_flow("expression", node_range(value, source)));
        issues.push(issue);
    });
}

const IDEMNECANT_OPERATORS: [&str; 5] = ["-", "/", "%", "^", "&^"];
const IDEMPOTENT_OPERATORS: [&str; 4] = ["&&", "||", "&", "|"];

fn check_redundant_operation(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "binary_expression" {
            return;
        }
        let Some(operator) = operator_text(node, source) else {
            return;
        };
        let redundant = IDEMNECANT_OPERATORS.contains(&operator)
            || IDEMPOTENT_OPERATORS.contains(&operator)
            || (operator == "+" && average_by_two(node, source, facts));
        if !redundant {
            return;
        }
        let Some((left, right)) = binary_operands(node) else {
            return;
        };
        if IDEMNECANT_OPERATORS.contains(&operator)
            && (is_basic_literal(left) || is_basic_literal(right))
        {
            return;
        }
        let Some(key) = expression_key(left, source, facts) else {
            return;
        };
        if expression_key(right, source, facts).as_ref() != Some(&key) {
            return;
        }
        let mut issue = Issue::new(
            REDUNDANT_OPERATION,
            "The $@ and $@ operand of this operation are identical.",
            node_range(node, source),
        );
        issue
            .flows
            .push(single_flow("left", node_range(left, source)));
        issue
            .flows
            .push(single_flow("right", node_range(right, source)));
        issues.push(issue);
    });
}

fn average_by_two(node: Node<'_>, source: &str, facts: &SemanticFacts) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "binary_expression" || operator_text(parent, source) != Some("/") {
        return false;
    }
    let Some((left, right)) = binary_operands(parent) else {
        return false;
    };
    strip_parens(left).id() == node.id()
        && eval_int(right, source, facts, &mut HashSet::new()) == Some(2)
}

fn check_redundant_recover(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "defer_statement" {
            return;
        }
        let Some(call) = node.named_child(0) else {
            return;
        };
        if call.kind() != "call_expression" {
            return;
        }
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        if function.kind() != "identifier"
            || text(function, source) != "recover"
            || facts.is_shadowed("recover", call.start_byte())
        {
            return;
        }
        push_simple(
            issues,
            REDUNDANT_RECOVER,
            "Deferred calls to 'recover' have no effect.",
            node_range(call, source),
        );
    });
}

fn integer_width_of(ty: &str) -> Option<(bool, i128)> {
    match ty.trim() {
        "int8" | "uint8" | "byte" => Some((false, 8)),
        "int16" | "uint16" => Some((false, 16)),
        "int32" | "uint32" | "rune" => Some((false, 32)),
        "int64" | "uint64" => Some((false, 64)),
        "int" | "uint" | "uintptr" => Some((true, 64)),
        _ => None,
    }
}

fn declared_integer_width(
    node: Node<'_>,
    source: &str,
    widths: &HashMap<String, String>,
) -> Option<(bool, i128)> {
    let stripped = strip_parens(node);
    if stripped.kind() == "int_literal" {
        return Some((true, 64));
    }
    if stripped.kind() == "identifier" {
        let ty = widths.get(text(stripped, source))?;
        return integer_width_of(ty);
    }
    if stripped.kind() == "call_expression" {
        let function = strip_parens(stripped.child_by_field_name("function")?);
        if function.kind() == "type_identifier" {
            return integer_width_of(text(function, source));
        }
    }
    None
}

fn collect_integer_widths(root: Node<'_>, source: &str) -> HashMap<String, String> {
    let mut widths = HashMap::new();
    walk(root, &mut |node| {
        let declared = match node.kind() {
            "var_spec" | "parameter_declaration" => node
                .child_by_field_name("type")
                .map(|ty| text(ty, source).to_owned()),
            "short_var_declaration" => short_conversion_type(node, source),
            _ => None,
        };
        let Some(ty) = declared else {
            return;
        };
        if integer_width_of(&ty).is_none() {
            return;
        }
        for name in declaration_names(node, source) {
            widths.insert(name, ty.clone());
        }
    });
    widths
}

fn short_conversion_type(node: Node<'_>, source: &str) -> Option<String> {
    let right = node.child_by_field_name("right")?;
    let value = right.named_child(0)?;
    if value.kind() != "call_expression" {
        return None;
    }
    let function = strip_parens(value.child_by_field_name("function")?);
    (function.kind() == "type_identifier").then(|| text(function, source).to_owned())
}

fn check_shift_out_of_range(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    let widths = collect_integer_widths(root, source);
    walk(root, &mut |node| {
        if node.kind() != "binary_expression" {
            return;
        }
        let Some(operator) = operator_text(node, source) else {
            return;
        };
        if !is_shift(operator) {
            return;
        }
        let Some((_, right)) = binary_operands(node) else {
            return;
        };
        let Some(amount) = eval_int(right, source, facts, &mut HashSet::new()) else {
            return;
        };
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let Some((at_most, bits)) = declared_integer_width(left, source, &widths) else {
            return;
        };
        if amount >= 0 && amount < bits {
            return;
        }
        let prefix = if at_most { "(at most) " } else { "" };
        push_simple(
            issues,
            SHIFT_OUT_OF_RANGE,
            format!(
                "Shifting a value of {prefix}{bits} bits by {amount} always yields either 0 or -1."
            ),
            node_range(node, source),
        );
    });
}
fn nearest_function(root: Node<'_>, at: usize) -> Option<Node<'_>> {
    let mut best: Option<Node<'_>> = None;
    walk(root, &mut |node| {
        if !matches!(
            node.kind(),
            "function_declaration" | "method_declaration" | "function_literal"
        ) {
            return;
        }
        let start = node.start_byte();
        if start <= at
            && at < node.end_byte()
            && best.is_none_or(|prior| start > prior.start_byte())
        {
            best = Some(node);
        }
    });
    best
}

fn check_unexpected_nil_value(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    imports: &crate::GoImports,
    issues: &mut Vec<Issue>,
) {
    let Some(alias) = imports.alias("github.com/pkg/errors") else {
        return;
    };
    let nil_locals = collect_nil_initialized_locals(root, source);
    walk(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        if function.kind() != "selector_expression" {
            return;
        }
        let Some((operand, field)) = binary_operands_selector(function) else {
            return;
        };
        if operand.kind() != "identifier"
            || text(operand, source) != alias
            || text(field, source) != "Wrap"
        {
            return;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let Some(first) = arguments.named_child(0) else {
            return;
        };
        if !wrapped_error_is_nil(first, node, root, source, facts, &nil_locals) {
            return;
        }
        push_simple(
            issues,
            UNEXPECTED_NIL_VALUE,
            "The first argument to 'errors.Wrap' is always nil.",
            node_range(first, source),
        );
    });
}

fn binary_operands_selector(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    Some((
        node.child_by_field_name("operand")?,
        node.child_by_field_name("field")?,
    ))
}

fn collect_nil_initialized_locals(root: Node<'_>, source: &str) -> Vec<NilLocal> {
    let mut locals = Vec::new();
    walk(root, &mut |node| {
        if node.kind() != "var_spec" {
            return;
        }
        if node.child_by_field_name("value").is_some() {
            return;
        }
        let (scope_start, scope_end) = declaration_scope(node, root);
        for name in declaration_names(node, source) {
            locals.push(NilLocal {
                name,
                declaration_end: node.end_byte(),
                scope_start,
                scope_end,
            });
        }
    });
    locals
}

struct NilLocal {
    name: String,
    declaration_end: usize,
    scope_start: usize,
    scope_end: usize,
}

fn wrapped_error_is_nil(
    first: Node<'_>,
    call: Node<'_>,
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    nil_locals: &[NilLocal],
) -> bool {
    let stripped = strip_parens(first);
    if stripped.kind() == "nil" {
        return true;
    }
    if stripped.kind() != "identifier" {
        return false;
    }
    let name = text(stripped, source);
    nil_local_is_still_nil(name, stripped, call, root, source, facts, nil_locals)
        || error_is_guarded_nil(stripped, root, source)
}

fn nil_local_is_still_nil(
    name: &str,
    use_site: Node<'_>,
    call: Node<'_>,
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    nil_locals: &[NilLocal],
) -> bool {
    let Some(local) = nil_locals.iter().find(|local| {
        local.name == name
            && local.scope_start <= call.start_byte()
            && call.end_byte() <= local.scope_end
            && local.declaration_end <= use_site.start_byte()
    }) else {
        return false;
    };
    if facts.is_shadowed(name, use_site.start_byte()) {
        return false;
    }
    !reassigned_between(root, name, local.declaration_end, call.start_byte(), source)
}

fn reassigned_between(root: Node<'_>, name: &str, from: usize, to: usize, source: &str) -> bool {
    let mut reassigned = false;
    walk(root, &mut |node| {
        if reassigned
            || !matches!(
                node.kind(),
                "assignment_statement" | "short_var_declaration"
            )
            || node.start_byte() <= from
            || node.end_byte() > to
        {
            return;
        }
        reassigned = assignment_lhs_identifiers_plain(node, source)
            .iter()
            .any(|lhs| lhs == name);
    });
    reassigned
}

fn assignment_lhs_identifiers_plain(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(left) = node.child_by_field_name("left") else {
        return Vec::new();
    };
    named_children(left)
        .into_iter()
        .filter(|child| child.kind() == "identifier")
        .map(|child| text(child, source).to_owned())
        .collect()
}

fn error_is_guarded_nil(use_site: Node<'_>, root: Node<'_>, source: &str) -> bool {
    nil_inside_equality_block(use_site, root, source)
        || after_exiting_nil_check(use_site, root, source)
}

fn nil_inside_equality_block(use_site: Node<'_>, root: Node<'_>, source: &str) -> bool {
    let mut guarded = false;
    walk(root, &mut |node| {
        if guarded || node.kind() != "if_statement" || node.end_byte() < use_site.end_byte() {
            return;
        }
        let Some(condition) = node.child_by_field_name("condition") else {
            return;
        };
        let Some(consequent) = node.child_by_field_name("consequence") else {
            return;
        };
        if !consequence_contains(consequent, use_site)
            || !is_nil_comparison(condition, "==", source)
        {
            return;
        }
        guarded = true;
    });
    guarded
}

fn consequence_contains(consequent: Node<'_>, use_site: Node<'_>) -> bool {
    let start = consequent.start_byte();
    start <= use_site.start_byte() && use_site.end_byte() <= consequent.end_byte()
}

fn is_nil_comparison(condition: Node<'_>, operator: &str, source: &str) -> bool {
    if condition.kind() != "binary_expression" || operator_text(condition, source) != Some(operator)
    {
        return false;
    }
    let Some((left, right)) = binary_operands(condition) else {
        return false;
    };
    strip_parens(left).kind() == "identifier" && strip_parens(right).kind() == "nil"
}

fn after_exiting_nil_check(use_site: Node<'_>, root: Node<'_>, source: &str) -> bool {
    let Some(enclosing) = nearest_statement_list(root, use_site.start_byte()) else {
        return false;
    };
    let mut guarded = false;
    for statement in named_children(enclosing) {
        if statement.start_byte() >= use_site.start_byte() {
            break;
        }
        if statement.kind() != "if_statement" {
            continue;
        }
        let Some(condition) = statement.child_by_field_name("condition") else {
            continue;
        };
        let Some(consequent) = statement.child_by_field_name("consequence") else {
            continue;
        };
        let condition_name = identifier_of_nil_comparison(condition, "!=", source);
        let Some(condition_name) = condition_name else {
            continue;
        };
        let use_name = text(strip_parens(use_site), source);
        if condition_name == use_name && block_terminates(consequent, source) {
            guarded = true;
        }
    }
    guarded
}

fn identifier_of_nil_comparison(
    condition: Node<'_>,
    operator: &str,
    source: &str,
) -> Option<String> {
    if condition.kind() != "binary_expression" || operator_text(condition, source) != Some(operator)
    {
        return None;
    }
    let (left, right) = binary_operands(condition)?;
    let identifier = strip_parens(left);
    if identifier.kind() != "identifier" || strip_parens(right).kind() != "nil" {
        return None;
    }
    Some(text(identifier, source).to_owned())
}

fn nearest_statement_list(root: Node<'_>, at: usize) -> Option<Node<'_>> {
    let mut best = None;
    walk(root, &mut |node| {
        if node.kind() != "statement_list" {
            return;
        }
        if node.start_byte() <= at && at < node.end_byte() {
            best = Some(node);
        }
    });
    best
}

fn check_unhandled_writable_file_close(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    imports: &crate::GoImports,
    issues: &mut Vec<Issue>,
) {
    let Some(alias) = imports.alias("os") else {
        return;
    };
    let opens = collect_writable_opens(root, alias, source);
    if opens.is_empty() {
        return;
    }
    for open in &opens {
        let Some(enclosing) = nearest_function(root, open.position) else {
            continue;
        };
        report_unhandled_closes(enclosing, open, root, source, facts, issues);
    }
}

struct WritableOpen {
    variable: String,
    position: usize,
    range: Range,
}

fn collect_writable_opens(root: Node<'_>, alias: &str, source: &str) -> Vec<WritableOpen> {
    let mut opens = Vec::new();
    walk(root, &mut |node| {
        if !matches!(
            node.kind(),
            "short_var_declaration" | "assignment_statement"
        ) {
            return;
        }
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        let Some(call) = right.named_child(0) else {
            return;
        };
        if call.kind() != "call_expression" {
            return;
        }
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        if !is_qualified_member(function, alias, "OpenFile", source) {
            return;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return;
        };
        let Some(flags) = arguments.named_child(1) else {
            return;
        };
        if !mentions_writable_flag(flags, alias, source) {
            return;
        }
        let Some(variable) = first_left_identifier(node, source) else {
            return;
        };
        opens.push(WritableOpen {
            variable,
            position: node.end_byte(),
            range: node_range(call, source),
        });
    });
    opens
}

fn is_qualified_member(node: Node<'_>, qualifier: &str, member: &str, source: &str) -> bool {
    node.kind() == "selector_expression"
        && binary_operands_selector(node).is_some_and(|(operand, field)| {
            operand.kind() == "identifier"
                && text(operand, source) == qualifier
                && text(field, source) == member
        })
}

fn mentions_writable_flag(flags: Node<'_>, alias: &str, source: &str) -> bool {
    let mut writable = false;
    walk(flags, &mut |node| {
        if writable {
            return;
        }
        if is_qualified_member(node, alias, "O_WRONLY", source)
            || is_qualified_member(node, alias, "O_RDWR", source)
        {
            writable = true;
        }
    });
    writable
}

fn first_left_identifier(node: Node<'_>, source: &str) -> Option<String> {
    let left = node.child_by_field_name("left")?;
    let first = left.named_child(0)?;
    (first.kind() == "identifier").then(|| text(first, source).to_owned())
}

fn report_unhandled_closes(
    enclosing: Node<'_>,
    open: &WritableOpen,
    _root: Node<'_>,
    source: &str,
    _facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    let mut closes = Vec::new();
    walk(enclosing, &mut |node| {
        if node.start_byte() <= open.position {
            return;
        }
        let is_deferred = node.kind() == "defer_statement";
        if !is_deferred && node.kind() != "expression_statement" {
            return;
        }
        let Some(call) = node.named_child(0) else {
            return;
        };
        if call.kind() != "call_expression" {
            return;
        }
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        if !is_qualified_member(function, &open.variable, "Close", source) {
            return;
        }
        closes.push((is_deferred, node_range(call, source), call.end_byte()));
    });
    for (deferred, range, end) in closes {
        if variable_reassigned_in(enclosing, &open.variable, open.position, end, source) {
            continue;
        }
        if handled_sync_before(enclosing, &open.variable, end, source) {
            continue;
        }
        let _ = deferred;
        let mut issue = Issue::new(
            UNHANDLED_WRITABLE_FILE_CLOSE,
            "File handle may be writable as a result of data flow from a $@ and closing it may result in data loss upon failure, which is not handled explicitly.",
            range,
        );
        issue
            .flows
            .push(single_flow("the os.OpenFile call", open.range.clone()));
        issues.push(issue);
    }
}

fn variable_reassigned_in(
    enclosing: Node<'_>,
    variable: &str,
    from: usize,
    to: usize,
    source: &str,
) -> bool {
    let mut reassigned = false;
    walk(enclosing, &mut |node| {
        if reassigned
            || !matches!(
                node.kind(),
                "assignment_statement" | "short_var_declaration"
            )
            || node.start_byte() <= from
            || node.end_byte() > to
        {
            return;
        }
        reassigned = assignment_lhs_identifiers_plain(node, source)
            .iter()
            .any(|lhs| lhs == variable);
    });
    reassigned
}

fn handled_sync_before(enclosing: Node<'_>, variable: &str, before: usize, source: &str) -> bool {
    let mut handled = false;
    walk(enclosing, &mut |node| {
        if handled || node.kind() != "call_expression" || node.end_byte() > before {
            return;
        }
        let parent_is_void = node.parent().is_some_and(|parent| {
            matches!(parent.kind(), "expression_statement" | "defer_statement")
        });
        if parent_is_void {
            return;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        handled = is_qualified_member(function, variable, "Sync", source);
    });
    handled
}

fn check_missing_error_check(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    let callees = nil_with_error_callees(root, source);
    if callees.is_empty() {
        return;
    }
    walk(root, &mut |node| {
        if !matches!(
            node.kind(),
            "short_var_declaration" | "assignment_statement"
        ) {
            return;
        }
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        let Some(call) = right.named_child(0) else {
            return;
        };
        if call.kind() != "call_expression" {
            return;
        }
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        if function.kind() != "identifier"
            || facts.is_shadowed(text(function, source), call.start_byte())
            || !callees.contains(text(function, source))
        {
            return;
        }
        let names = assignment_lhs_identifiers_plain(node, source);
        if names.len() != 2 {
            return;
        }
        let Some(enclosing) = nearest_statement_list(root, node.start_byte()) else {
            return;
        };
        if let Some(deref) = unchecked_deref_after(enclosing, node, &names[0], &names[1], source) {
            let mut issue = Issue::new(
                MISSING_ERROR_CHECK,
                "$@ may be nil at this dereference because $@ may not have been checked.",
                node_range(deref, source),
            );
            issue
                .flows
                .push(single_flow("this value", node_range(deref, source)));
            issue.flows.push(single_flow(
                "the results of this call",
                node_range(call, source),
            ));
            issues.push(issue);
        }
    });
}

fn nil_with_error_callees(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut callees = HashSet::new();
    for function in top_level_functions(root) {
        if !returns_nil_with_error(function, source) {
            continue;
        }
        let Some(name) = function.child_by_field_name("name") else {
            continue;
        };
        callees.insert(text(name, source).to_owned());
    }
    callees
}

fn returns_nil_with_error(function: Node<'_>, source: &str) -> bool {
    let Some(result) = function.child_by_field_name("result") else {
        return false;
    };
    let results: Vec<String> = named_children(result)
        .into_iter()
        .filter_map(|parameter| {
            parameter
                .child_by_field_name("type")
                .map(|ty| text(ty, source).to_owned())
        })
        .collect();
    if results.len() != 2 {
        return false;
    }
    let pointer_like = results[0].starts_with('*')
        || results[0].starts_with("[]")
        || results[0].starts_with("map[")
        || results[0].starts_with("interface");
    if !pointer_like || results[1] != "error" {
        return false;
    }
    has_nil_plus_error_return(function, source)
}

fn return_values(statement: Node<'_>) -> Vec<Node<'_>> {
    match statement.named_child(0) {
        Some(list) if list.kind() == "expression_list" => named_children(list),
        _ => Vec::new(),
    }
}

fn has_nil_plus_error_return(function: Node<'_>, _source: &str) -> bool {
    let mut found = false;
    walk(function, &mut |node| {
        if found || node.kind() != "return_statement" {
            return;
        }
        let values = return_values(node);
        if values.len() < 2 {
            return;
        }
        let first_is_nil = strip_parens(values[0]).kind() == "nil";
        let second_not_nil = strip_parens(values[1]).kind() != "nil";
        if first_is_nil && second_not_nil {
            found = true;
        }
    });
    found
}

fn unchecked_deref_after<'a>(
    list: Node<'a>,
    assignment: Node<'_>,
    pointer: &str,
    error: &str,
    source: &str,
) -> Option<Node<'a>> {
    let mut statements = named_children(list);
    let index = statements
        .iter()
        .position(|statement| statement.id() == assignment.id())?;
    for statement in statements.drain(index + 1..) {
        if let Some(deref) = dereference_of(statement, pointer, source) {
            return Some(deref);
        }
        if checks_value_or_reassigns(statement, pointer, error, source) {
            return None;
        }
        if is_control_statement(statement) {
            return None;
        }
    }
    None
}

fn dereference_of<'a>(node: Node<'a>, variable: &str, source: &str) -> Option<Node<'a>> {
    let mut found = None;
    walk(node, &mut |inner| {
        if found.is_some() {
            return;
        }
        let operand = match inner.kind() {
            "selector_expression" | "index_expression" => inner.child_by_field_name("operand"),
            "unary_expression" if operator_text(inner, source) == Some("*") => {
                inner.child_by_field_name("operand")
            }
            _ => None,
        };
        let Some(operand) = operand else {
            return;
        };
        let stripped = strip_parens(operand);
        if stripped.kind() == "identifier" && text(stripped, source) == variable {
            found = Some(inner);
        }
    });
    found
}

fn checks_value_or_reassigns(
    statement: Node<'_>,
    pointer: &str,
    error: &str,
    source: &str,
) -> bool {
    let mut checked = false;
    walk(statement, &mut |node| {
        if checked {
            return;
        }
        if matches!(
            node.kind(),
            "assignment_statement" | "short_var_declaration"
        ) && assignment_lhs_identifiers_plain(node, source)
            .iter()
            .any(|lhs| lhs == pointer || lhs == error)
        {
            checked = true;
            return;
        }
        let compares = node.kind() == "binary_expression"
            && matches!(operator_text(node, source), Some("==" | "!="))
            && binary_operands(node).is_some_and(|(left, right)| {
                identifier_text(left, pointer, source)
                    || identifier_text(right, pointer, source)
                    || identifier_text(left, error, source)
                    || identifier_text(right, error, source)
            });
        if compares {
            checked = true;
            return;
        }
        if node.kind() == "call_expression" {
            let Some(arguments) = node.child_by_field_name("arguments") else {
                return;
            };
            let mut passes = false;
            walk(arguments, &mut |argument| {
                if argument.kind() == "identifier"
                    && (text(argument, source) == pointer || text(argument, source) == error)
                {
                    passes = true;
                }
            });
            checked = passes;
            return;
        }
        if node.kind() == "type_assertion_expression" {
            let Some(operand) = node.child_by_field_name("operand") else {
                return;
            };
            checked = identifier_text(operand, pointer, source);
        }
    });
    checked
}

fn identifier_text(node: Node<'_>, name: &str, source: &str) -> bool {
    let stripped = strip_parens(node);
    stripped.kind() == "identifier" && text(stripped, source) == name
}

fn is_control_statement(statement: Node<'_>) -> bool {
    matches!(
        statement.kind(),
        "if_statement"
            | "for_statement"
            | "expression_switch_statement"
            | "type_switch_statement"
            | "select_statement"
            | "go_statement"
            | "defer_statement"
            | "labeled_statement"
    )
}

fn block_terminates(block: Node<'_>, source: &str) -> bool {
    let Some(last) = named_children(block).pop() else {
        return false;
    };
    statement_terminates(last, source)
}

fn statement_terminates(statement: Node<'_>, source: &str) -> bool {
    match statement.kind() {
        "return_statement"
        | "break_statement"
        | "continue_statement"
        | "goto_statement"
        | "fallthrough_statement" => true,
        "if_statement" => {
            let terminates = statement
                .child_by_field_name("consequence")
                .is_some_and(|block| block_terminates(block, source));
            terminates
                && statement
                    .child_by_field_name("alternative")
                    .is_some_and(|alternative| match alternative.kind() {
                        "block" => block_terminates(alternative, source),
                        "if_statement" => statement_terminates(alternative, source),
                        _ => false,
                    })
        }
        "expression_statement" => terminating_call(statement, source),
        _ => false,
    }
}

fn terminating_call(statement: Node<'_>, source: &str) -> bool {
    let Some(expression) = statement.named_child(0) else {
        return false;
    };
    if expression.kind() != "call_expression" {
        return false;
    }
    let Some(function) = expression.child_by_field_name("function") else {
        return false;
    };
    let name = match function.kind() {
        "identifier" => text(function, source).to_owned(),
        "selector_expression" => function
            .child_by_field_name("field")
            .map(|field| text(field, source).to_owned())
            .unwrap_or_default(),
        _ => return false,
    };
    matches!(
        name.as_str(),
        "panic" | "Exit" | "Fatal" | "Fatalf" | "Fatalln"
    )
}

fn check_unreachable_statements(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        if node.kind() != "statement_list" {
            return;
        }
        let mut terminated = false;
        for statement in named_children(node) {
            if terminated && !unreachable_allowlisted(statement, source) {
                push_simple(
                    issues,
                    UNREACHABLE_STATEMENT,
                    "This statement is unreachable.",
                    node_range(statement, source),
                );
            }
            terminated = terminated || statement_terminates(statement, source);
        }
    });
}

fn unreachable_allowlisted(statement: Node<'_>, source: &str) -> bool {
    if statement.kind() == "expression_statement" {
        return allowlisted_call(statement, source);
    }
    if statement.kind() == "return_statement" {
        return return_values(statement)
            .iter()
            .all(|value| allowed_return_value(*value, source));
    }
    false
}

fn allowlisted_call(statement: Node<'_>, source: &str) -> bool {
    let Some(expression) = statement.named_child(0) else {
        return false;
    };
    if expression.kind() != "call_expression" {
        return false;
    }
    let Some(function) = expression.child_by_field_name("function") else {
        return false;
    };
    let name = match function.kind() {
        "identifier" => text(function, source),
        "selector_expression" => {
            let Some(field) = function.child_by_field_name("field") else {
                return false;
            };
            text(field, source)
        }
        _ => return false,
    };
    let lowered = name.to_lowercase();
    lowered == "panic" || lowered.starts_with("error")
}

fn allowed_return_value(value: Node<'_>, source: &str) -> bool {
    let stripped = strip_parens(value);
    if is_basic_literal(stripped) {
        return true;
    }
    if stripped.kind() == "unary_expression" {
        return operator_text(stripped, source) != Some("&")
            && stripped
                .child_by_field_name("operand")
                .is_some_and(|operand| allowed_return_value(operand, source));
    }
    if stripped.kind() == "composite_literal" {
        let Some(body) = stripped.child_by_field_name("body") else {
            return false;
        };
        return named_children(body)
            .iter()
            .all(|element| allowed_return_value(*element, source));
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OccurrenceKind {
    Write,
    CompoundWrite,
    FieldWrite,
    Read,
    AddressOf,
    SelectorBase,
}

#[derive(Debug, Clone)]
struct ChainLevel {
    list_id: usize,
    index: usize,
    kind: &'static str,
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct Occurrence {
    name: String,
    field: Option<String>,
    position: usize,
    range: Range,
    kind: OccurrenceKind,
    chain: Vec<ChainLevel>,
    simple: bool,
}

fn collect_occurrences(
    list: Node<'_>,
    chain: &mut Vec<ChainLevel>,
    out: &mut Vec<Occurrence>,
    source: &str,
    facts: &SemanticFacts,
) {
    for (index, statement) in named_children(list).into_iter().enumerate() {
        chain.push(ChainLevel {
            list_id: list.id(),
            index,
            kind: statement.kind(),
            start: statement.start_byte(),
            end: statement.end_byte(),
        });
        descend_for_occurrences(statement, chain, out, source, facts);
        chain.pop();
    }
}

fn descend_for_occurrences(
    node: Node<'_>,
    chain: &mut Vec<ChainLevel>,
    out: &mut Vec<Occurrence>,
    source: &str,
    facts: &SemanticFacts,
) {
    if node.kind() == "statement_list" {
        collect_occurrences(node, chain, out, source, facts);
        return;
    }
    if node.kind() == "identifier" {
        record_occurrence(node, chain, out, source, facts);
        return;
    }
    for child in named_children(node) {
        descend_for_occurrences(child, chain, out, source, facts);
    }
}

fn record_occurrence(
    node: Node<'_>,
    chain: &mut [ChainLevel],
    out: &mut Vec<Occurrence>,
    source: &str,
    facts: &SemanticFacts,
) {
    let kind = occurrence_kind(node, source);
    let field = occurrence_field(node, kind, source);
    let simple = kind == OccurrenceKind::Write && write_rhs_is_simple(node, source, facts);
    out.push(Occurrence {
        name: text(node, source).to_owned(),
        field,
        position: node.start_byte(),
        range: node_range(node, source),
        kind,
        chain: chain.to_vec(),
        simple,
    });
}

fn occurrence_kind(node: Node<'_>, source: &str) -> OccurrenceKind {
    let Some(parent) = node.parent() else {
        return OccurrenceKind::Read;
    };
    match parent.kind() {
        "unary_expression" if operator_text(parent, source) == Some("&") => {
            OccurrenceKind::AddressOf
        }
        "selector_expression" => {
            let is_operand = parent
                .child_by_field_name("operand")
                .is_some_and(|operand| operand.id() == node.id());
            if !is_operand {
                return OccurrenceKind::Read;
            }
            selector_use_kind(parent, source)
        }
        "expression_list" => list_position_kind(node, parent, source),
        _ => OccurrenceKind::Read,
    }
}

fn list_position_kind(_node: Node<'_>, list: Node<'_>, source: &str) -> OccurrenceKind {
    let Some(grandparent) = list.parent() else {
        return OccurrenceKind::Read;
    };
    let is_left_list = matches!(
        grandparent.kind(),
        "assignment_statement" | "short_var_declaration"
    ) && grandparent
        .child_by_field_name("left")
        .is_some_and(|left| left.id() == list.id());
    if !is_left_list {
        return OccurrenceKind::Read;
    }
    if grandparent.kind() == "assignment_statement"
        && operator_text(grandparent, source) != Some("=")
    {
        return OccurrenceKind::CompoundWrite;
    }
    OccurrenceKind::Write
}
fn selector_use_kind(selector: Node<'_>, source: &str) -> OccurrenceKind {
    let Some(list) = selector
        .parent()
        .filter(|parent| parent.kind() == "expression_list")
    else {
        return OccurrenceKind::SelectorBase;
    };
    let is_lhs = list.parent().is_some_and(|grandparent| {
        matches!(
            grandparent.kind(),
            "assignment_statement" | "short_var_declaration"
        ) && grandparent
            .child_by_field_name("left")
            .is_some_and(|left| left.id() == list.id())
    });
    if !is_lhs {
        return OccurrenceKind::SelectorBase;
    }
    let field = selector
        .child_by_field_name("field")
        .map(|field| text(field, source).to_owned());
    if field.is_some() {
        OccurrenceKind::FieldWrite
    } else {
        OccurrenceKind::SelectorBase
    }
}

fn occurrence_field(node: Node<'_>, kind: OccurrenceKind, source: &str) -> Option<String> {
    if kind != OccurrenceKind::FieldWrite {
        return None;
    }
    let parent = node.parent()?;
    parent
        .child_by_field_name("field")
        .map(|field| text(field, source).to_owned())
}

fn write_rhs_is_simple(node: Node<'_>, source: &str, facts: &SemanticFacts) -> bool {
    let Some(parent) = node
        .parent()
        .filter(|parent| parent.kind() == "expression_list")
    else {
        return false;
    };
    let Some(grandparent) = parent.parent() else {
        return false;
    };
    let Some(right) = grandparent.child_by_field_name("right") else {
        return false;
    };
    let index = named_children(parent)
        .into_iter()
        .position(|child| child.id() == node.id());
    let Some(index) = index else {
        return false;
    };
    let Some(value) = right.named_child(index) else {
        return false;
    };
    let stripped = strip_parens(value);
    if is_basic_literal(stripped) {
        return true;
    }
    if stripped.kind() == "identifier"
        && eval_int(stripped, source, facts, &mut HashSet::new()).is_some()
    {
        return true;
    }
    stripped.kind() == "composite_literal"
        && stripped
            .child_by_field_name("body")
            .is_none_or(|body| body.named_child_count() == 0)
}

fn dominates(later: &Occurrence, earlier: &Occurrence) -> bool {
    let (before, after) = (&earlier.chain, &later.chain);
    let depth = before.len().min(after.len());
    for level in 0..depth {
        let b = &before[level];
        let a = &after[level];
        if b.list_id != a.list_id {
            return false;
        }
        if a.index > b.index {
            return true;
        }
        if a.index < b.index {
            return false;
        }
    }
    false
}

fn enclosing_loop(occurrence: &Occurrence) -> Option<&ChainLevel> {
    occurrence
        .chain
        .iter()
        .rev()
        .find(|level| level.kind == "for_statement")
}

fn dead_store_range(occurrence: &Occurrence, later: &[Occurrence]) -> Option<Range> {
    let same_name: Vec<&Occurrence> = later
        .iter()
        .filter(|other| other.name == occurrence.name)
        .collect();
    if let Some(loop_level) = enclosing_loop(occurrence) {
        let read_inside_loop = same_name.iter().any(|other| {
            matches!(
                other.kind,
                OccurrenceKind::Read
                    | OccurrenceKind::CompoundWrite
                    | OccurrenceKind::SelectorBase
                    | OccurrenceKind::FieldWrite
            ) && other.position >= loop_level.start
                && other.position < loop_level.end
        });
        if read_inside_loop {
            return None;
        }
    }
    let first_read = same_name
        .iter()
        .filter(|other| {
            matches!(
                other.kind,
                OccurrenceKind::Read
                    | OccurrenceKind::CompoundWrite
                    | OccurrenceKind::SelectorBase
                    | OccurrenceKind::FieldWrite
            )
        })
        .map(|other| other.position)
        .min();
    match first_read {
        None => Some(occurrence.range.clone()),
        Some(read_at) => same_name
            .iter()
            .filter(|other| {
                other.kind == OccurrenceKind::Write
                    && other.position > occurrence.position
                    && other.position < read_at
                    && !read_inside_statement(other, read_at)
            })
            .any(|other| dominates(other, occurrence))
            .then_some(occurrence.range.clone()),
    }
}

fn read_inside_statement(write: &Occurrence, read_at: usize) -> bool {
    write
        .chain
        .last()
        .is_some_and(|level| level.start <= read_at && read_at <= level.end)
}

fn named_result_names(function: Node<'_>, source: &str) -> Vec<String> {
    let Some(result) = function.child_by_field_name("result") else {
        return Vec::new();
    };
    named_children(result)
        .into_iter()
        .filter(|parameter| parameter.child_by_field_name("name").is_some())
        .filter_map(|parameter| parameter.child_by_field_name("name"))
        .map(|name| text(name, source).to_owned())
        .collect()
}

fn check_useless_local_assignment(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    for function in top_level_functions(root) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let named_results: HashSet<String> =
            named_result_names(function, source).into_iter().collect();
        let mut chain = Vec::new();
        let mut occurrences = Vec::new();
        collect_occurrences(body, &mut chain, &mut occurrences, source, facts);
        for (index, occurrence) in occurrences.iter().enumerate() {
            if occurrence.kind != OccurrenceKind::Write
                || occurrence.name == "_"
                || named_results.contains(&occurrence.name)
                || occurrence.simple
            {
                continue;
            }
            if occurrences.iter().any(|other| {
                other.name == occurrence.name && other.kind == OccurrenceKind::AddressOf
            }) {
                continue;
            }
            if let Some(range) = dead_store_range(occurrence, &occurrences[index + 1..]) {
                push_simple(
                    issues,
                    USELESS_ASSIGNMENT_TO_LOCAL,
                    format!("This definition of {} is never used.", occurrence.name),
                    range,
                );
            }
        }
    }
}

fn field_read_after(body: Node<'_>, field: &str, after: usize, source: &str) -> bool {
    let mut found = false;
    walk(body, &mut |node| {
        if found || node.kind() != "selector_expression" || node.start_byte() <= after {
            return;
        }
        let Some(field_node) = node.child_by_field_name("field") else {
            return;
        };
        if text(field_node, source) != field {
            return;
        }
        let is_lhs = node
            .parent()
            .filter(|parent| parent.kind() == "expression_list")
            .is_some_and(|list| {
                list.parent().is_some_and(|grandparent| {
                    matches!(
                        grandparent.kind(),
                        "assignment_statement" | "short_var_declaration"
                    ) && grandparent
                        .child_by_field_name("left")
                        .is_some_and(|left| left.id() == list.id())
                })
            });
        if !is_lhs {
            found = true;
        }
    });
    found
}

fn declared_value_local(body: Node<'_>, variable: &str, before: usize, source: &str) -> bool {
    let mut value = false;
    walk(body, &mut |node| {
        if value
            || node.end_byte() > before
            || !matches!(node.kind(), "short_var_declaration" | "var_spec")
        {
            return;
        }
        let declares = if node.kind() == "var_spec" {
            declaration_names(node, source)
        } else {
            assignment_lhs_identifiers_plain(node, source)
        };
        if !declares.iter().any(|name| name == variable) {
            return;
        }
        if node.kind() == "var_spec" {
            let ty = node
                .child_by_field_name("type")
                .map(|ty| text(ty, source).to_owned());
            value = ty.is_some_and(|ty| !ty.starts_with('*') && !ty.starts_with("map["));
            return;
        }
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        let Some(decl_value) = right.named_child(0) else {
            return;
        };
        value = strip_parens(decl_value).kind() == "composite_literal";
    });
    value
}

fn check_useless_field_assignment(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    for function in top_level_functions(root) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let mut chain = Vec::new();
        let mut occurrences = Vec::new();
        collect_occurrences(body, &mut chain, &mut occurrences, source, facts);
        for occurrence in &occurrences {
            if occurrence.kind != OccurrenceKind::FieldWrite {
                continue;
            }
            let Some(field) = &occurrence.field else {
                continue;
            };
            let variable = &occurrence.name;
            if occurrences
                .iter()
                .any(|other| other.name == *variable && other.kind == OccurrenceKind::AddressOf)
            {
                continue;
            }
            let only_selector_uses = {
                let declaring_write = occurrences
                    .iter()
                    .filter(|other| other.name == *variable && other.kind == OccurrenceKind::Write)
                    .map(|other| other.position)
                    .min();
                occurrences.iter().all(|other| {
                    other.name != *variable
                        || matches!(
                            other.kind,
                            OccurrenceKind::SelectorBase | OccurrenceKind::FieldWrite
                        )
                        || (other.kind == OccurrenceKind::Write
                            && declaring_write == Some(other.position))
                })
            };
            if !only_selector_uses
                || !declared_value_local(body, variable, occurrence.position, source)
                || field_read_after(body, field, occurrence.position, source)
            {
                continue;
            }
            push_simple(
                issues,
                USELESS_ASSIGNMENT_TO_FIELD,
                format!("This assignment to {field} is useless since its value is never read."),
                occurrence.range.clone(),
            );
        }
    }
}

fn collect_interface_names(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut interfaces = HashSet::new();
    walk(root, &mut |node| {
        if node.kind() != "type_spec" {
            return;
        }
        let Some(ty) = node.child_by_field_name("type") else {
            return;
        };
        if ty.kind() != "interface_type" {
            return;
        }
        if let Some(name) = node.child_by_field_name("name") {
            interfaces.insert(text(name, source).to_owned());
        }
    });
    interfaces
}

struct ConcreteLocal {
    name: String,
    ty: String,
    declaration_end: usize,
}

fn collect_concrete_locals(
    root: Node<'_>,
    source: &str,
    interfaces: &HashSet<String>,
) -> Vec<ConcreteLocal> {
    let mut locals = Vec::new();
    walk(root, &mut |node| {
        let (names, ty) = match node.kind() {
            "var_spec" => (
                declaration_names(node, source),
                node.child_by_field_name("type")
                    .map(|ty| text(ty, source).to_owned()),
            ),
            "short_var_declaration" => (
                assignment_lhs_identifiers_plain(node, source),
                concrete_literal_type(node, source),
            ),
            _ => (Vec::new(), None),
        };
        let Some(ty) = ty else {
            return;
        };
        if interfaces.contains(&ty) {
            return;
        }
        for name in names {
            locals.push(ConcreteLocal {
                name,
                ty: ty.clone(),
                declaration_end: node.end_byte(),
            });
        }
    });
    locals
}

fn concrete_literal_type(node: Node<'_>, source: &str) -> Option<String> {
    let right = node.child_by_field_name("right")?;
    let value = strip_parens(right.named_child(0)?);
    let type_name = match value.kind() {
        "unary_expression" => {
            let operand = strip_parens(value.child_by_field_name("operand")?);
            if operator_text(value, source) != Some("&") {
                return None;
            }
            operand
                .child_by_field_name("type")
                .map(|ty| text(ty, source).to_owned())
        }
        "composite_literal" => value
            .child_by_field_name("type")
            .map(|ty| text(ty, source).to_owned()),
        "call_expression" => {
            let function = strip_parens(value.child_by_field_name("function")?);
            let name = text(function, source);
            if function.kind() == "identifier" && name == "new" {
                value
                    .child_by_field_name("arguments")
                    .and_then(|arguments| arguments.named_child(0))
                    .map(|argument| text(argument, source).to_owned())
            } else if function.kind() == "type_identifier" {
                Some(name.to_owned())
            } else {
                None
            }
        }
        _ => None,
    }?;
    let type_name = type_name.trim_start_matches('*').trim().to_owned();
    Some(type_name)
}

fn concrete_value_type(value: Node<'_>, source: &str, locals: &[ConcreteLocal]) -> Option<String> {
    let stripped = strip_parens(value);
    if stripped.kind() == "identifier" {
        let name = text(stripped, source);
        return locals
            .iter()
            .rev()
            .find(|local| local.name == name && local.declaration_end <= stripped.start_byte())
            .map(|local| local.ty.clone());
    }
    concrete_literal_type_source(stripped, source)
}

fn concrete_literal_type_source(value: Node<'_>, source: &str) -> Option<String> {
    let type_name = match value.kind() {
        "unary_expression" => {
            if operator_text(value, source) != Some("&") {
                return None;
            }
            let operand = strip_parens(value.child_by_field_name("operand")?);
            operand
                .child_by_field_name("type")
                .map(|ty| text(ty, source).to_owned())
        }
        "composite_literal" => value
            .child_by_field_name("type")
            .map(|ty| text(ty, source).to_owned()),
        "call_expression" => {
            let function = strip_parens(value.child_by_field_name("function")?);
            let name = text(function, source);
            if function.kind() == "identifier" && name == "new" {
                value
                    .child_by_field_name("arguments")
                    .and_then(|arguments| arguments.named_child(0))
                    .map(|argument| text(argument, source).to_owned())
            } else if function.kind() == "type_identifier" {
                Some(name.to_owned())
            } else {
                None
            }
        }
        _ => return None,
    }?;
    Some(type_name.trim_start_matches('*').trim().to_owned())
}

fn check_impossible_interface_nil_check(
    root: Node<'_>,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    let interfaces = collect_interface_names(root, source);
    if interfaces.is_empty() {
        return;
    }
    let locals = collect_concrete_locals(root, source, &interfaces);
    walk(root, &mut |node| {
        if node.kind() != "var_spec" {
            return;
        }
        let Some(ty) = node.child_by_field_name("type") else {
            return;
        };
        if !interfaces.contains(text(ty, source)) {
            return;
        }
        let Some(value) = node.child_by_field_name("value") else {
            return;
        };
        let value = match value.kind() {
            "expression_list" => value.named_child(0),
            _ => Some(value),
        };
        let Some(value) = value else {
            return;
        };
        let Some(_concrete) = concrete_value_type(value, source, &locals) else {
            return;
        };
        let names = declaration_names(node, source);
        if names.len() != 1 {
            return;
        }
        let variable = names[0].clone();
        let declaration_end = node.end_byte();
        report_nil_comparisons(root, &variable, declaration_end, source, facts, issues);
    });
}

fn report_nil_comparisons(
    root: Node<'_>,
    variable: &str,
    declaration_end: usize,
    source: &str,
    facts: &SemanticFacts,
    issues: &mut Vec<Issue>,
) {
    walk(root, &mut |node| {
        if node.kind() != "binary_expression"
            || !matches!(operator_text(node, source), Some("==" | "!="))
        {
            return;
        }
        let Some((left, right)) = binary_operands(node) else {
            return;
        };
        let left_identifier = strip_parens(left);
        let right_identifier = strip_parens(right);
        let (wrapped, nil_side) = if left_identifier.kind() == "identifier"
            && text(left_identifier, source) == variable
        {
            (left_identifier, right)
        } else if right_identifier.kind() == "identifier"
            && text(right_identifier, source) == variable
        {
            (right_identifier, left)
        } else {
            return;
        };
        if strip_parens(nil_side).kind() != "nil"
            || strip_parens(nil_side).start_byte() < declaration_end
            || facts.is_shadowed(variable, wrapped.start_byte())
            || reassigned_between(root, variable, declaration_end, node.start_byte(), source)
        {
            return;
        }
        push_simple(
            issues,
            IMPOSSIBLE_INTERFACE_NIL_CHECK,
            "This value can never be nil, since it is a wrapped interface value.",
            node_range(wrapped, source),
        );
    });
}

fn check_useless_expression(root: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    walk(root, &mut |node| {
        if node.kind() != "expression_statement" {
            return;
        }
        let Some(expression) = node.named_child(0) else {
            return;
        };
        if expression_has_side_effect(expression, source) {
            return;
        }
        push_simple(
            issues,
            USELESS_EXPRESSION,
            "This expression has no effect.",
            node_range(expression, source),
        );
    });
}

fn expression_has_side_effect(node: Node<'_>, source: &str) -> bool {
    match strip_parens(node).kind() {
        "identifier"
        | "int_literal"
        | "float_literal"
        | "imaginary_literal"
        | "interpreted_string_literal"
        | "raw_string_literal"
        | "rune_literal"
        | "true"
        | "false"
        | "nil" => false,
        "unary_expression" => {
            operator_text(node, source) == Some("<-")
                || node
                    .child_by_field_name("operand")
                    .is_some_and(|operand| expression_has_side_effect(operand, source))
        }
        "binary_expression" => binary_operands(node).is_some_and(|(left, right)| {
            expression_has_side_effect(left, source) || expression_has_side_effect(right, source)
        }),
        "selector_expression" => node
            .child_by_field_name("operand")
            .is_some_and(|operand| expression_has_side_effect(operand, source)),
        "index_expression" => match (
            node.child_by_field_name("operand"),
            node.child_by_field_name("index"),
        ) {
            (Some(operand), Some(index)) => {
                expression_has_side_effect(operand, source)
                    || expression_has_side_effect(index, source)
            }
            _ => true,
        },
        "composite_literal" => node
            .child_by_field_name("body")
            .is_some_and(|body| contains_side_effect(body, source)),
        _ => true,
    }
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
    fn type_alias_targets_resolve_at_their_declaration() {
        let signed = "package p\ntype Signed = int\nfunc f() { type int = uint; var value Signed; if value < 0 {} }\n";
        assert!(!keys(signed).iter().any(|key| key == NEGATIVE_LENGTH_CHECK));
        for unsigned in [
            "package p\ntype Unsigned = uint\nfunc f() { type uint = int; var value Unsigned; if value < 0 {} }\n",
            "package p\nfunc f() { type A = uint; { type uint = int; type B = A; var value B; if value < 0 {} } }\n",
        ] {
            assert_eq!(
                keys(unsigned)
                    .iter()
                    .filter(|key| key.as_str() == NEGATIVE_LENGTH_CHECK)
                    .count(),
                1,
                "{unsigned}"
            );
        }
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
    #[test]
    fn identical_value_comparison_ignores_nan_and_feature_flags() {
        let source = "package p\nfunc f(x int) bool { return x == x }\n";
        assert_eq!(keys(source), vec![COMPARISON_IDENTICAL]);
        let clean = [
            "package p\nfunc f(v float64) bool { return v != v }\n",
            "package p\nconst level = 3\nfunc f(x int) bool { return x == level }\n",
            "package p\nfunc f(x, y int) bool { return x == y }\n",
        ];
        for case in clean {
            assert!(keys(case).is_empty(), "{case}");
        }
    }

    #[test]
    fn constant_length_check_inside_incrementing_loop_is_flagged() {
        let source = r"package p
func f(a []int) {
    for i := 0; i < len(a); i++ {
        if len(a) != 3 {
            _ = a[i]
        }
    }
}
";
        assert_eq!(keys(source), vec![CONSTANT_LENGTH_COMPARISON]);
        let clean = [
            "package p\nfunc f(a []int) { for i := range a { _ = a[i] } }\n",
            "package p\nfunc f(a []int) { for i := 0; i < len(a); i++ { if len(a) != 3 { _ = a[0] } } }\n",
        ];
        for case in clean {
            assert!(keys(case).is_empty(), "{case}");
        }
    }

    #[test]
    fn duplicate_if_branches_are_reported_on_the_condition() {
        let source = "package p\nfunc f(x int, y *int) { if x > 0 { *y = 1 } else { *y = 1 } }\n";
        assert_eq!(keys(source), vec![DUPLICATE_BRANCHES]);
        assert!(
            keys("package p\nfunc f(x int, y *int) { if x > 0 { *y = 1 } else { *y = 2 } }\n")
                .is_empty()
        );
    }

    #[test]
    fn wrapped_interface_value_needs_no_nil_check() {
        let source = r"package p
type I interface{ M() }
type Impl struct{}
func f() {
    var impl *Impl
    var w I = impl
    if w != nil {
    }
}
";
        assert_eq!(keys(source), vec![IMPOSSIBLE_INTERFACE_NIL_CHECK]);
        let clean = [
            "package p\ntype I interface{ M() }\nfunc f() { var w I; if w != nil {} }\n",
            "package p\ntype Impl struct{}\nfunc f() { var impl *Impl; if impl != nil {} }\n",
        ];
        for case in clean {
            assert!(keys(case).is_empty(), "{case}");
        }
    }

    #[test]
    fn loop_direction_conflicts_respect_unsigned_idioms() {
        let source = "package p\nfunc f(n int) { for i := 0; i < n; i-- {} }\n";
        assert_eq!(keys(source), vec![INCONSISTENT_LOOP_DIRECTION]);
        let clean = [
            "package p\nfunc f(n int) { for i := 0; i < n; i++ {} }\n",
            "package p\nfunc f(n uint) { for u := n; u <= n; u-- {} }\n",
        ];
        for case in clean {
            assert!(keys(case).is_empty(), "{case}");
        }
    }

    #[test]
    fn off_by_one_length_comparison_needs_the_guarded_read() {
        let source = "package p\nfunc f(xs []int, i int) { if i <= len(xs) { _ = xs[i] } }\n";
        assert_eq!(keys(source), vec![INDEX_OUT_OF_BOUNDS]);
        let clean = [
            "package p\nfunc f(xs []int, i int) { if i < len(xs) { _ = xs[i] } }\n",
            "package p\nfunc f(xs []int, i int) { if i != len(xs) { _ = xs[i] } }\n",
        ];
        for case in clean {
            assert!(keys(case).is_empty(), "{case}");
        }
    }

    #[test]
    fn missing_error_check_requires_same_file_nil_returning_callee() {
        let source = r"package p
type T struct{ Name string }
func makeT(fail bool) (*T, error) {
    if fail {
        return nil, errFailed
    }
    return &T{}, nil
}
func caller(fail bool) string {
    v, err := makeT(fail)
    name := v.Name
    _ = err
    return name
}
";
        assert_eq!(keys(source), vec![MISSING_ERROR_CHECK]);
        let checked = source.replace(
            "    name := v.Name",
            "    if err != nil {\n        return \"\"\n    }\n    name := v.Name",
        );
        assert!(keys(&checked).is_empty());
    }

    #[test]
    fn self_assignments_are_reported_but_constants_are_not() {
        let source = "package p\nfunc f(x int) int {\n    y := x\n    y = y\n    return y\n}\n";
        assert_eq!(keys(source), vec![REDUNDANT_ASSIGNMENT]);
        assert!(keys("package p\nfunc f(x, y int) int {\n    x = y\n    return x\n}\n").is_empty());
    }

    #[test]
    fn identical_operands_cover_idemnecant_and_idempotent_operators() {
        let source = "package p\nfunc f(x bool, y int) {\n    _ = y - y\n    _ = x && x\n}\n";
        assert_eq!(keys(source).len(), 2);
        assert!(keys(source).iter().all(|key| key == REDUNDANT_OPERATION));
        let clean = [
            "package p\nfunc f(y int) { _ = 1 - 1 }\n",
            "package p\nfunc f(x, y bool) { _ = x && y }\n",
            "package p\nfunc f(x, y int) { _ = x - y }\n",
        ];
        for case in clean {
            assert!(keys(case).is_empty(), "{case}");
        }
        let average = "package p\nfunc f(x int) int { return (x + x) / 2 }\n";
        assert!(keys(average).iter().all(|key| key == REDUNDANT_OPERATION));
    }

    #[test]
    fn deferred_recover_direct_calls_have_no_effect() {
        let source = "package p\nfunc f() {\n    defer recover()\n}\n";
        assert_eq!(keys(source), vec![REDUNDANT_RECOVER]);
        let clean =
            "package p\nfunc f() {\n    defer func() {\n        _ = recover()\n    }()\n}\n";
        assert!(keys(clean).is_empty());
    }

    #[test]
    fn shift_amounts_beyond_the_left_type_are_flagged() {
        let source = "package p\nfunc f() int8 {\n    var x int8 = 1\n    return x << 9\n}\n";
        assert_eq!(keys(source), vec![SHIFT_OUT_OF_RANGE]);
        let clean = [
            "package p\nfunc f() int8 { var x int8 = 1; return x << 7 }\n",
            "package p\nfunc f() int { return 1 << 63 }\n",
            "package p\nfunc f(s uint) int { return 1 << s }\n",
        ];
        for case in clean {
            assert!(keys(case).is_empty(), "{case}");
        }
    }

    #[test]
    fn wrapped_nil_errors_need_the_pkg_errors_import() {
        let source = r#"package p
import "github.com/pkg/errors"
func f() error {
    var err error
    return errors.Wrap(err, "context")
}
"#;
        assert_eq!(keys(source), vec![UNEXPECTED_NIL_VALUE]);
        let literal = r#"package p
import "github.com/pkg/errors"
func f() error {
    return errors.Wrap(nil, "context")
}
"#;
        assert_eq!(keys(literal), vec![UNEXPECTED_NIL_VALUE]);
        let live = r#"package p
import "github.com/pkg/errors"
func f() error {
    err := doWork()
    return errors.Wrap(err, "context")
}
func doWork() error { return nil }
"#;
        assert!(keys(live).is_empty());
        assert!(keys("package p\nfunc f() error { return wrap(nil) }\n").is_empty());
    }

    #[test]
    fn deferred_closes_of_writable_handles_are_reported_with_flow() {
        let source = r#"package p
import "os"
func write() error {
    fh, err := os.OpenFile("data", os.O_WRONLY, 0o644)
    if err != nil {
        return err
    }
    defer fh.Close()
    return nil
}
"#;
        let issues = analyze_github_quality(source);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule_key, UNHANDLED_WRITABLE_FILE_CLOSE);
        assert_eq!(issues[0].flows.len(), 1);
        let synced = source.replace(
            "    defer fh.Close()",
            "    if serr := fh.Sync(); serr != nil {\n        return serr\n    }\n    defer fh.Close()",
        );
        assert!(keys(&synced).is_empty());
        let readonly = source.replace("os.O_WRONLY", "os.O_RDONLY");
        assert!(keys(&readonly).is_empty());
        let handled_close = source.replace("    defer fh.Close()", "    return fh.Close()");
        assert!(keys(&handled_close).is_empty());
    }

    #[test]
    fn statements_after_terminators_skip_constant_returns() {
        let source = "package p\nfunc f() int {\n    return 1\n    y := 2\n    _ = y\n}\n";
        assert_eq!(
            keys(source)
                .iter()
                .filter(|key| key == &UNREACHABLE_STATEMENT)
                .count(),
            2
        );
        let allowlisted = "package p\nfunc g() {\n    panic(\"boom\")\n    return\n}\n";
        assert!(keys(allowlisted).is_empty());
        let exiting = "package p\nimport \"os\"\nfunc h() {\n    os.Exit(1)\n    println(1)\n}\n";
        assert_eq!(keys(exiting), vec![UNREACHABLE_STATEMENT]);
    }

    #[test]
    fn dead_local_stores_respect_reads_and_loops() {
        let source = r"package p
func f(x int) int {
    y := compute(x)
    y = x
    return y
}
func compute(x int) int { return x }
";
        assert_eq!(keys(source), vec![USELESS_ASSIGNMENT_TO_LOCAL]);
        let live = "package p\nfunc f(x int) int {\n    y := compute(x)\n    return y\n}\nfunc compute(x int) int { return x }\n";
        assert!(keys(live).is_empty());
        let loop_carried = r"package p
func g(n int) int {
    total := 0
    for i := 0; i < n; i++ {
        total = i
        total += 1
    }
    return total
}
";
        assert!(keys(loop_carried).is_empty());
    }

    #[test]
    fn dead_field_stores_need_value_receivers_without_later_reads() {
        let source = r"package p
type P struct{ A int }
func f() {
    p := P{}
    p.A = 1
    p.A = 2
}
";
        assert_eq!(
            keys(source)
                .iter()
                .filter(|key| key == &USELESS_ASSIGNMENT_TO_FIELD)
                .count(),
            2
        );
        let read = source.replace("    p.A = 2", "    p.A = 2\n    _ = p.A");
        assert!(keys(&read).is_empty());
    }

    #[test]
    fn void_expressions_without_effects_are_flagged() {
        let source = "package p\nfunc f(x int) {\n    x == 1\n    x + 1\n}\n";
        assert_eq!(keys(source).len(), 2);
        assert!(keys(source).iter().all(|key| key == USELESS_EXPRESSION));
        let clean = [
            "package p\nfunc f(x int, ch chan int) {\n    <-ch\n}\n",
            "package p\nfunc g(x int) { println(x) }\n",
        ];
        for case in clean {
            assert!(keys(case).is_empty(), "{case}");
        }
    }
}
