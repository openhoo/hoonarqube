// Residual rule machinery for 'expression' (extracted from lib.rs).
use crate::rules::shared::CONSOLE_METHODS;
use crate::rules::shared::argument_expression;
use crate::support::{
    IssueSink, RuleScope, member_object, member_root_name, member_rooted_at, unparenthesized,
};
use oxc_ast::ast::{
    AssignmentTarget, BindingIdentifier, CallExpression, Expression, Function, MemberExpression,
    ObjectExpression, ObjectPropertyKind, PropertyKey, PropertyKind, ThisExpression,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_member_expression, walk_variable_declaration};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;
use std::collections::HashSet;

/// `S106`, `S1442`, `S6637`, and `S6676`.
pub(crate) fn check_logging_and_binding_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
) {
    if member_rooted_at(member, "console") && CONSOLE_METHODS.contains(&property) {
        sink.emit_span(
            RuleScope::Both,
            "S106",
            "Unexpected console statement.",
            it.callee.span(),
        );
    }
    if property == "alert" {
        sink.emit_span(
            RuleScope::JsOnly,
            "S1442",
            "Remove this use of \"alert\".",
            it.callee.span(),
        );
    }
    if property == "bind"
        && it.arguments.len() == 1
        && argument_expression(&it.arguments[0]).is_some()
        && bind_target_is_unnecessary(member_object(member))
    {
        let span = match member {
            MemberExpression::StaticMemberExpression(member) => member.property.span(),
            _ => it.callee.span(),
        };
        sink.emit_span(
            RuleScope::Both,
            "S6637",
            "The function binding is unnecessary.",
            span,
        );
    }
    if matches!(property, "call" | "apply") && it.arguments.len() == 1 {
        sink.emit_span(
            RuleScope::Both,
            "S6676",
            "Invoke this function directly instead of via \"call\"/\"apply\".",
            it.callee.span(),
        );
    }
}

/// `S6666`, `S6959`, `S2871`, `S6653`, `S2685`, `S6654`, and `S6661`.
pub(crate) fn check_collection_and_object_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
) {
    if property == "apply"
        && it.arguments.len() == 2
        && argument_expression(&it.arguments[1])
            .is_some_and(|argument| matches!(argument, Expression::ArrayExpression(_)))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6666",
            "Use spread syntax instead of \"apply\".",
            it.arguments[1].span(),
        );
    }
    if property == "reduce" && it.arguments.len() == 1 {
        sink.emit_span(
            RuleScope::Both,
            "S6959",
            "Provide an initial accumulator value to this \"reduce\".",
            it.callee.span(),
        );
    }
    if matches!(property, "sort" | "toSorted") && it.arguments.is_empty() {
        let span = match member {
            MemberExpression::StaticMemberExpression(member) => member.property.span(),
            _ => it.callee.span(),
        };
        sink.emit_span(
            RuleScope::Both,
            "S2871",
            "Provide a compare function to avoid sorting elements alphabetically.",
            span,
        );
    }
    if property == "hasOwnProperty" {
        sink.emit_span(
            RuleScope::Both,
            "S6653",
            "Use \"Object.hasOwn()\" instead of \"hasOwnProperty()\".",
            it.callee.span(),
        );
    }
    if matches!(property, "caller" | "callee") && member_root_name(member) == Some("arguments") {
        sink.emit_span(
            RuleScope::Both,
            "S2685",
            "Avoid arguments.callee.",
            it.callee.span(),
        );
    }
    if property == "assign"
        && member_rooted_at(member, "Object")
        && it
            .arguments
            .first()
            .and_then(argument_expression)
            .is_some_and(|argument| matches!(argument, Expression::ObjectExpression(_)))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6661",
            "Use object spread syntax instead of \"Object.assign\".",
            it.arguments[0].span(),
        );
    }
}

/// Whether the `.bind(...)` receiver is a function whose own `this` is not
/// needed. Arrow functions never own `this`; ordinary functions do unless
/// their body (excluding nested ordinary functions) uses it.
fn bind_target_is_unnecessary(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::ArrowFunctionExpression(_) => true,
        Expression::FunctionExpression(function) => !function_uses_this(function),
        _ => false,
    }
}

fn function_uses_this(function: &Function<'_>) -> bool {
    let mut collector = ThisUsageCollector::default();
    collector.visit_formal_parameters(&function.params);
    if let Some(body) = function.body.as_deref() {
        collector.visit_function_body(body);
    }
    collector.found_this
}

#[derive(Default)]
struct ThisUsageCollector {
    found_this: bool,
}

impl<'a> Visit<'a> for ThisUsageCollector {
    fn visit_this_expression(&mut self, _: &ThisExpression) {
        self.found_this = true;
    }

    // A nested ordinary function has its own `this`, so it must not make the
    // enclosing function appear to use its receiver.
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6637_flags_arrow_and_plain_functions_without_this() {
        let findings = js_keys(
            "const arrow = (() => 1).bind(receiver);\n\
             const plain = function () {}.bind(receiver);\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6637"), 2);
    }

    #[test]
    fn s6637_preserves_outer_this_and_meaningful_arguments() {
        let findings = js_keys(
            "const uses = function () { return this.value; }.bind(receiver);\n\
             const nested_arrow = function () { return () => this.value; }.bind(receiver);\n\
             const nested_function = function () { return function () { return this.value; }; }.bind(receiver);\n\
             const extra_args = function () {}.bind(receiver, value);\n\
             const spread = function () {}.bind(...values);\n",
        );
        // The nested ordinary function owns its own `this`; only the outer
        // binding is unnecessary in that case.
        assert_eq!(count_key(&findings, "javascript:S6637"), 1);
    }

    #[test]
    fn s6637_keeps_the_legacy_good_fixture_as_positive_evidence() {
        let findings = js_keys("const f = function () {}.bind(this);\n");
        assert_eq!(count_key(&findings, "javascript:S6637"), 1);
    }

    #[test]
    fn s6666_reports_pinned_express_nonliteral_apply_sites() {
        // #252: verbatim expressjs/express@53d4a0d606c0388f764f192b306ce0e90200e7e8
        // lib/application.js (MIT). SonarQube 26.8.0.126808 (Sonar way)
        // reports exactly these three S6666 sites: the array-producing
        // `slice.call(...)` argument and the array-valued `args` identifiers.
        let report = js(include_str!(
            "../../../fixtures/shapes/express-application.js"
        ));
        let sites: Vec<((u32, u32), (u32, u32))> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S6666")
            .map(|issue| {
                (
                    (issue.range.start.line, issue.range.start.column),
                    (issue.range.end.line, issue.range.end.column),
                )
            })
            .collect();
        assert_eq!(
            sites,
            vec![
                ((479, 4), (479, 56)),
                ((499, 4), (499, 40)),
                ((605, 9), (605, 42)),
            ]
        );
    }

    #[test]
    fn s6666_reports_pinned_axios_spread_site() {
        // #252: verbatim axios/axios@18e7dfedf30c96e58652887f930642ae82e0130c
        // lib/helpers/spread.js (MIT). SonarQube 26.8.0.126808 (Sonar way)
        // reports the `callback.apply(null, arr)` wrapper call at line 26.
        let report = js(include_str!(
            "../../../fixtures/shapes/axios-spread.js"
        ));
        let sites: Vec<((u32, u32), (u32, u32), &str)> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S6666")
            .map(|issue| {
                (
                    (issue.range.start.line, issue.range.start.column),
                    (issue.range.end.line, issue.range.end.column),
                    issue.message.as_str(),
                )
            })
            .collect();
        assert_eq!(
            sites,
            vec![(
                (26, 11),
                (26, 36),
                "Use the spread operator instead of '.apply()'."
            )]
        );
    }

    #[test]
    fn s6666_reports_spread_safe_nonliteral_array_arguments() {
        let findings = js_keys(
            "fn.apply(null, args);\n\
             fn.apply(undefined, args);\n\
             obj.method.apply(obj, values);\n\
             obj.method.apply(obj, slice.call(arguments, 1));\n\
             fn.apply(null, [1, 2]);\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6666"), 5);
    }

    #[test]
    fn s6666_spread_unsafe_and_unrelated_calls_stay_clean() {
        let findings = js_keys(
            "h.apply(ctx, args);\n\
             obj.method.apply(other, args);\n\
             h.apply(args);\n\
             h.call(null, args);\n\
             Reflect.apply(h, this, args);\n\
             h(...args);\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6666"), 0);
    }
}

/// `S6654` for one member use: reads, call callees, and write targets of
/// the deprecated `__proto__` prototype accessor report at the property
/// span. A receiver that resolves to a const object literal declaring an
/// own `__proto__` member stays silent — that spelling is an ordinary own
/// property, not the inherited accessor.
pub(crate) fn check_proto_member_use(
    sink: &mut IssueSink,
    member: &MemberExpression<'_>,
    own_proto_bindings: &HashSet<SymbolId>,
    semantic: Option<&Semantic<'_>>,
) {
    let Some((receiver, span)) = proto_accessor_member(member) else {
        return;
    };
    emit_proto_member_use(sink, receiver, span, own_proto_bindings, semantic);
}

/// The write-target form of [`proto_accessor_member`]: assignment LHS
/// members live in the separate `AssignmentTarget` enum.
pub(crate) fn proto_write_target<'a, 'b>(
    target: &'a AssignmentTarget<'b>,
) -> Option<(&'a Expression<'b>, Span)> {
    match target {
        AssignmentTarget::StaticMemberExpression(member) if member.property.name == "__proto__" => {
            Some((&member.object, member.property.span))
        }
        AssignmentTarget::ComputedMemberExpression(member) => match &member.expression {
            Expression::StringLiteral(literal) if literal.value == "__proto__" => {
                Some((&member.object, literal.span))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Emits the `S6654` finding when the receiver does not provably own the
/// member.
pub(crate) fn emit_proto_member_use(
    sink: &mut IssueSink,
    receiver: &Expression<'_>,
    span: Span,
    own_proto_bindings: &HashSet<SymbolId>,
    semantic: Option<&Semantic<'_>>,
) {
    if receiver_is_own_proto_binding(receiver, own_proto_bindings, semantic) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S6654",
        "Use \"Object.getPrototypeOf()\"/\"Object.setPrototypeOf()\" instead of \"__proto__\".",
        span,
    );
}

/// The receiver and property span when `member` names the deprecated
/// accessor — statically or through a literal computed key.
fn proto_accessor_member<'a, 'b>(
    member: &'a MemberExpression<'b>,
) -> Option<(&'a Expression<'b>, Span)> {
    match member {
        MemberExpression::StaticMemberExpression(member) => {
            (member.property.name == "__proto__").then_some((&member.object, member.property.span))
        }
        MemberExpression::ComputedMemberExpression(member) => match &member.expression {
            Expression::StringLiteral(literal) if literal.value == "__proto__" => {
                Some((&member.object, literal.span))
            }
            _ => None,
        },
        MemberExpression::PrivateFieldExpression(_) => None,
    }
}

/// Whether the receiver resolves to a const object literal declaring an
/// own `__proto__` member.
fn receiver_is_own_proto_binding(
    receiver: &Expression<'_>,
    own_proto_bindings: &HashSet<SymbolId>,
    semantic: Option<&Semantic<'_>>,
) -> bool {
    let Expression::Identifier(reference) = unparenthesized(receiver) else {
        return false;
    };
    semantic.is_some_and(|semantic| {
        semantic
            .scoping()
            .get_reference(reference.reference_id())
            .symbol_id()
            .is_some_and(|symbol| own_proto_bindings.contains(&symbol))
    })
}

/// Const bindings whose initializer is an object literal declaring an own
/// `__proto__` member. Symbol-keyed resolution keeps shadowed names out of
/// the suppression set.
pub(crate) fn collect_own_proto_bindings(program: &oxc_ast::ast::Program<'_>) -> HashSet<SymbolId> {
    let mut collector = OwnProtoBindingCollector {
        bindings: HashSet::new(),
    };
    collector.visit_program(program);
    collector.bindings
}

struct OwnProtoBindingCollector {
    bindings: HashSet<SymbolId>,
}

impl<'a> Visit<'a> for OwnProtoBindingCollector {
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        // Only `const` bindings keep their initializer's identity; a
        // rebindable `let`/`var` receiver would be a guess.
        if it.kind == VariableDeclarationKind::Const {
            for declarator in &it.declarations {
                self.collect_declarator(declarator);
            }
        }
        walk_variable_declaration(self, it);
    }
}

impl OwnProtoBindingCollector {
    fn collect_declarator(&mut self, declarator: &VariableDeclarator<'_>) {
        let Some(init) = declarator.init.as_ref() else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(init) else {
            return;
        };
        if !object_has_own_proto_member(object) {
            return;
        }
        if let Some(symbol) = declarator
            .id
            .get_binding_identifier()
            .map(BindingIdentifier::symbol_id)
        {
            self.bindings.insert(symbol);
        }
    }
}

/// Whether the literal declares an own `__proto__` member. Methods,
/// accessors, shorthand, and computed keys always create own members; the
/// plain colon form (`{ __proto__: value }`, string-keyed included) is the
/// prototype setter itself, so it stays reported.
fn object_has_own_proto_member(object: &ObjectExpression<'_>) -> bool {
    object.properties.iter().any(|property| match property {
        ObjectPropertyKind::ObjectProperty(property) => {
            let computed_proto_key = property.computed
                && matches!(&property.key, PropertyKey::StringLiteral(literal) if literal.value == "__proto__");
            if computed_proto_key {
                return true;
            }
            let static_proto_key = match &property.key {
                PropertyKey::StaticIdentifier(identifier) => identifier.name == "__proto__",
                PropertyKey::StringLiteral(literal) => {
                    !property.computed && literal.value == "__proto__"
                }
                _ => false,
            };
            static_proto_key
                && (property.method || property.kind != PropertyKind::Init || property.shorthand)
        }
        ObjectPropertyKind::SpreadProperty(_) => false,
    })
}

/// Whether the `if` test conditions on `Object.setPrototypeOf`
/// availability. The guarded `__proto__` write inside is deliberate
/// compatibility code for engines without the modern API, so it is not a
/// replacement candidate.
pub(crate) fn test_references_set_prototype_of(test: &Expression<'_>) -> bool {
    let mut detector = SetPrototypeOfDetector::default();
    detector.visit_expression(test);
    detector.found
}

#[derive(Default)]
struct SetPrototypeOfDetector {
    found: bool,
}

impl<'a> Visit<'a> for SetPrototypeOfDetector {
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if let MemberExpression::StaticMemberExpression(member) = it
            && member.property.name == "setPrototypeOf"
            && matches!(&member.object, Expression::Identifier(object) if object.name == "Object")
        {
            self.found = true;
        }
        walk_member_expression(self, it);
    }
}
