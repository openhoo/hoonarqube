// Family walker for 'tier_c' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::engine::scope_model::{
    FunctionCensus, LiteralKind, kind_is_composite, kind_is_numeric, literal_kind,
};
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::{
    IssueSink, LineIndex, RuleScope, callee_name, expression_root_name, member_object, span_issue,
    unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AwaitExpression, BinaryExpression, BinaryOperator, CallExpression, Expression,
    ExpressionStatement, MemberExpression,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_await_expression, walk_binary_expression, walk_call_expression, walk_expression_statement,
    walk_member_expression,
};
use oxc_span::{GetSpan, Span};

/// All Tier-C operator/literal and function-census rules in one traversal.
pub(crate) fn check_tier_c_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut census = FunctionCensus::default();
    census.visit_program(program);
    let mut collector = TierCLiteralCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    let mut await_collector = TierCAwaitCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        census: &census,
    };
    await_collector.visit_program(program);
    collector.sink.issues.extend(await_collector.sink.issues);
    let mut usage_collector = TierCCallUsageCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        census: &census,
        suppress_span: None,
    };
    usage_collector.visit_program(program);
    collector.sink.issues.extend(usage_collector.sink.issues);
    // `S3800`: file-local functions whose returns mix literal kinds.
    for facts in census.functions.values() {
        let mut kinds = facts.return_kinds.clone();
        kinds.sort();
        kinds.dedup();
        if kinds.len() > 1 {
            collector.sink.issues.push(span_issue(
                index,
                format!("{}:S3800", language.prefix()),
                "Refactor this function so that it always returns the same type.",
                facts.span,
            ));
        }
    }
    // `S2301`: parameters that only select the function's behavior.
    for facts in census.functions.values() {
        if let Some(span) = facts.selector_span {
            collector.sink.issues.push(span_issue(
                index,
                format!("{}:S2301", language.prefix()),
                "This parameter only selects the behavior of this function; split it instead.",
                span,
            ));
        }
    }
    collector.sink.issues
}

/// Tier-C collector for call-usage checks driven by the function census.
pub(crate) struct TierCCallUsageCollector<'census, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) census: &'census FunctionCensus,
    /// Span of the direct call of the enclosing expression statement, whose
    // value legitimately goes unused.
    pub(crate) suppress_span: Option<Span>,
}

impl<'a> Visit<'a> for TierCCallUsageCollector<'_, '_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        let direct_call = match unparenthesized(&it.expression) {
            Expression::CallExpression(call) => Some(call.span()),
            _ => None,
        };
        let saved = self.suppress_span;
        if direct_call.is_some() {
            self.suppress_span = direct_call;
        }
        walk_expression_statement(self, it);
        self.suppress_span = saved;
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if self.suppress_span != Some(it.span())
            && let Some(name) = callee_name(it)
            && let Some(facts) = self.census.functions.get(name)
            && facts.is_void()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3699",
                "The return value of this void function should not be used.",
                it.span(),
            );
        }
        walk_call_expression(self, it);
    }
}

/// Tier-C collector for `await` over non-promises.
pub(crate) struct TierCAwaitCollector<'census, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) census: &'census FunctionCensus,
}

impl<'a> Visit<'a> for TierCAwaitCollector<'_, '_> {
    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        self.check_awaited_value(&it.argument);
        walk_await_expression(self, it);
    }
}

impl TierCAwaitCollector<'_, '_> {
    /// `S4123`: awaited values that are provably not promises.
    pub(crate) fn check_awaited_value(&mut self, argument: &Expression<'_>) {
        let flagged = match unparenthesized(argument) {
            Expression::StringLiteral(_)
            | Expression::TemplateLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::ArrayExpression(_)
            | Expression::ObjectExpression(_) => true,
            Expression::Identifier(identifier) => identifier.name == "undefined",
            Expression::CallExpression(call) => match &call.callee {
                Expression::Identifier(callee) => {
                    if self.is_known_sync_local(&callee.name) {
                        true
                    } else {
                        SYNC_GLOBAL_APIS.contains(&callee.name.as_str())
                    }
                }
                Expression::StaticMemberExpression(member) => SYNC_MEMBER_ROOTS
                    .contains(&expression_root_name(&member.object).unwrap_or_default()),
                _ => false,
            },
            _ => false,
        };
        if flagged {
            self.sink.emit_span(
                RuleScope::Both,
                "S4123",
                "This value is not a promise; 'await' has no effect here.",
                argument.span(),
            );
        }
    }

    pub(crate) fn is_known_sync_local(&self, name: &str) -> bool {
        self.census
            .functions
            .get(name)
            .is_some_and(|facts| !facts.r#async)
    }
}

/// Member roots whose calls are synchronous (`S4123`).
pub(crate) const SYNC_MEMBER_ROOTS: [&str; 7] = [
    "Math", "Object", "JSON", "Reflect", "Array", "Date", "Number",
];

/// Plain globals whose calls are synchronous (`S4123`).
pub(crate) const SYNC_GLOBAL_APIS: [&str; 9] = [
    "parseInt",
    "parseFloat",
    "isNaN",
    "isFinite",
    "btoa",
    "atob",
    "String",
    "Number",
    "Boolean",
];

/// Tier-C collector for operator/literal findings.
pub(crate) struct TierCLiteralCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for TierCLiteralCollector<'_> {
    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        self.check_string_addition(it);
        self.check_dissimilar_strict_equality(it);
        self.check_in_with_primitive(it);
        self.check_relational_composite_operand(it);
        self.check_arithmetic_non_number(it);
        self.check_nan_fold(it);
        walk_binary_expression(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        self.check_array_string_index(it);
        walk_member_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_nan_parse(it);
        self.check_builtin_signature(it);
        walk_call_expression(self, it);
    }
}

impl TierCLiteralCollector<'_> {
    /// `S3402`: `'str' + <non-string literal>` operand pairs.
    pub(crate) fn check_string_addition(&mut self, expression: &BinaryExpression<'_>) {
        if expression.operator != BinaryOperator::Addition {
            return;
        }
        let mixed = matches!(
            (
                literal_kind(&expression.left),
                literal_kind(&expression.right),
            ),
            (Some(LiteralKind::String), Some(kind)) | (Some(kind), Some(LiteralKind::String))
                if kind != LiteralKind::String
        );
        if mixed {
            self.sink.emit_span(
                RuleScope::Both,
                "S3402",
                "Convert this non-string operand explicitly instead of relying on '+'.",
                expression.span(),
            );
        }
    }

    /// `S3403`: `===`/`!==` between literals of different categories.
    pub(crate) fn check_dissimilar_strict_equality(&mut self, expression: &BinaryExpression<'_>) {
        if !matches!(
            expression.operator,
            BinaryOperator::StrictEquality | BinaryOperator::StrictInequality
        ) {
            return;
        }
        let (Some(left), Some(right)) = (
            literal_kind(&expression.left),
            literal_kind(&expression.right),
        ) else {
            return;
        };
        if left != right {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3403",
                "This strict comparison between dissimilar types is always false.",
                expression.span(),
            );
        }
    }

    /// `S3785`: `in` used with a primitive-typed right-hand side.
    pub(crate) fn check_in_with_primitive(&mut self, expression: &BinaryExpression<'_>) {
        if expression.operator != BinaryOperator::In {
            return;
        }
        if matches!(
            literal_kind(&expression.right),
            Some(
                LiteralKind::String
                    | LiteralKind::Number
                    | LiteralKind::BigInt
                    | LiteralKind::Boolean
                    | LiteralKind::Null
                    | LiteralKind::Undefined
            )
        ) {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3785",
                "'in' checks object members; this right operand is a primitive.",
                expression.span(),
            );
        }
    }

    /// `S3579`: string-literal indexes into array-shaped receivers.
    pub(crate) fn check_array_string_index(&mut self, member: &MemberExpression<'_>) {
        let MemberExpression::ComputedMemberExpression(computed) = member else {
            return;
        };
        let Expression::StringLiteral(_) = unparenthesized(&computed.expression) else {
            return;
        };
        let array_shaped = match unparenthesized(member_object(member)) {
            Expression::ArrayExpression(_) => true,
            Expression::CallExpression(call) => {
                ARRAY_RETURNING_APIS.contains(&sink_callee_name(&call.callee).unwrap_or_default())
            }
            _ => false,
        };
        if array_shaped {
            self.sink.emit_span(
                RuleScope::Both,
                "S3579",
                "Use a numeric index to access this array element.",
                member.span(),
            );
        }
    }

    /// `S3758`: relational comparisons over composite literals.
    pub(crate) fn check_relational_composite_operand(&mut self, expression: &BinaryExpression<'_>) {
        if !matches!(
            expression.operator,
            BinaryOperator::LessThan
                | BinaryOperator::GreaterThan
                | BinaryOperator::LessEqualThan
                | BinaryOperator::GreaterEqualThan
        ) {
            return;
        }
        let composite = literal_kind(&expression.left).is_some_and(kind_is_composite)
            || literal_kind(&expression.right).is_some_and(kind_is_composite);
        if composite {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3758",
                "This comparison coerces the operand to '[object Object]'.",
                expression.span(),
            );
        }
    }

    /// `S3760`: arithmetic operators over non-numeric operands.
    pub(crate) fn check_arithmetic_non_number(&mut self, expression: &BinaryExpression<'_>) {
        let (Some(left), Some(right)) = (
            literal_kind(&expression.left),
            literal_kind(&expression.right),
        ) else {
            return;
        };
        if kind_is_numeric(left) && kind_is_numeric(right) {
            return;
        }
        let flagged = match expression.operator {
            // `'str' + x` pairs are `S3402`'s territory; plain numeric
            // additions are fine. Anything else adding up is coercion.
            BinaryOperator::Addition => {
                left != LiteralKind::String
                    && right != LiteralKind::String
                    && (!kind_is_numeric(left) || !kind_is_numeric(right))
            }
            BinaryOperator::Subtraction
            | BinaryOperator::Multiplication
            | BinaryOperator::Division
            | BinaryOperator::Remainder
            | BinaryOperator::Exponential => true,
            _ => false,
        };
        if flagged {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3760",
                "Arithmetic here relies on implicit coercion and may produce 'NaN'.",
                expression.span(),
            );
        }
    }

    /// `S3757`: literal folds that always produce 'NaN'.
    pub(crate) fn check_nan_fold(&mut self, expression: &BinaryExpression<'_>) {
        let is_zero = |operand: &Expression| {
            matches!(
                unparenthesized(operand),
                Expression::NumericLiteral(literal) if literal.value == 0.0
            )
        };
        let is_infinity = |operand: &Expression| {
            matches!(
                unparenthesized(operand),
                Expression::Identifier(identifier) if identifier.name == "Infinity"
            )
        };
        let nan = match expression.operator {
            BinaryOperator::Division => is_zero(&expression.left) && is_zero(&expression.right),
            BinaryOperator::Multiplication => {
                (is_zero(&expression.left) && is_infinity(&expression.right))
                    || (is_infinity(&expression.left) && is_zero(&expression.right))
            }
            _ => false,
        };
        if nan {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3757",
                "This operation always produces 'NaN'.",
                expression.span(),
            );
        }
    }

    /// `S3757`: parse calls over non-numeric text and `Number(undefined)`.
    pub(crate) fn check_nan_parse(&mut self, call: &CallExpression<'_>) {
        let Some(name) = callee_name(call) else {
            return;
        };
        if !matches!(name, "parseInt" | "parseFloat" | "Number") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let flagged = match name {
            "parseInt" | "parseFloat" => {
                let Expression::StringLiteral(literal) = unparenthesized(argument) else {
                    return;
                };
                let text = literal.value.trim_start();
                let text = text.strip_prefix(['+', '-']).unwrap_or(text);
                !text.starts_with(|character: char| character.is_ascii_digit() || character == '.')
            }
            _ => {
                matches!(
                    unparenthesized(argument),
                    Expression::Identifier(identifier) if identifier.name == "undefined"
                ) || matches!(
                    unparenthesized(argument),
                    Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
                )
            }
        };
        if flagged {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3757",
                "This expression evaluates to 'NaN'.",
                call.span(),
            );
        }
    }

    /// `S3782`: literal arguments contradicting the built-ins' documented
    /// types: parse functions over composite/`null`/`undefined` text, bad
    /// radixes, and non-numeric `String.fromCharCode` codes.
    pub(crate) fn check_builtin_signature(&mut self, call: &CallExpression<'_>) {
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name == "fromCharCode"
            && expression_root_name(&member.object) == Some("String")
        {
            for argument in call.arguments.iter().filter_map(argument_expression) {
                if let Some(kind) = literal_kind(argument)
                    && !kind_is_numeric(kind)
                {
                    self.sink.emit_span(
                        RuleScope::JsOnly,
                        "S3782",
                        "String.fromCharCode expects numeric character codes.",
                        argument.span(),
                    );
                }
            }
            return;
        }
        let Some(name) = callee_name(call) else {
            return;
        };
        if matches!(name, "parseInt" | "parseFloat")
            && let Some(radix_kind) = call
                .arguments
                .get(1)
                .and_then(argument_expression)
                .and_then(literal_kind)
            && !kind_is_numeric(radix_kind)
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3782",
                "This parse function expects a numeric radix.",
                call.span(),
            );
        }
        if matches!(
            name,
            "parseInt"
                | "parseFloat"
                | "isNaN"
                | "isFinite"
                | "encodeURI"
                | "decodeURI"
                | "encodeURIComponent"
                | "decodeURIComponent"
        ) {
            self.check_string_expecting_builtin(call, name);
        }
    }

    /// Flags first arguments that cannot be stringified meaningfully.
    pub(crate) fn check_string_expecting_builtin(&mut self, call: &CallExpression<'_>, name: &str) {
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        if let Some(kind) = literal_kind(argument)
            && matches!(
                kind,
                LiteralKind::Object
                    | LiteralKind::Array
                    | LiteralKind::Function
                    | LiteralKind::RegExp
                    | LiteralKind::Null
                    | LiteralKind::Undefined
            )
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3782",
                &format!("'{name}' expects a string argument."),
                argument.span(),
            );
        }
    }
}

/// Member names whose call results are arrays (`S3579` receivers).
pub(crate) const ARRAY_RETURNING_APIS: [&str; 11] = [
    "split", "slice", "concat", "join", "reverse", "sort", "filter", "map", "splice", "flat",
    "flatMap",
];

/// Callee name for sink checks: plain identifier or last static member link
/// (`crypto.createHash` -> `createHash`).
pub(crate) fn sink_callee_name<'a>(callee: &'a Expression<'_>) -> Option<&'a str> {
    match callee {
        Expression::Identifier(identifier) => Some(&identifier.name),
        Expression::StaticMemberExpression(member) => Some(&member.property.name),
        _ => None,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_tier_c_rules(ctx.program, ctx.index, ctx.language)
}
