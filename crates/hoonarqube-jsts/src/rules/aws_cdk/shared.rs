// Shared CDK resolution engine for the `aws_cdk` family: a file-local,
// conservative re-implementation of the upstream SonarJS AWS helpers.
//
// The engine is fact-based: `Visit` hands out short-borrowed nodes that
// cannot be stored, so two pre-passes reduce the file to owned data —
// import/require bindings and digests of uniquely-declared variable
// initializers (literal values, dash-normalized fully-qualified names,
// object-literal shapes). Rule checks then run inline over each
// construct/call site through [`ValueView`], which transparently reads
// either a live expression or a pre-computed digest. Anything unresolvable
use crate::support::{IssueSink, RuleScope, property_key_name, unparenthesized};
use oxc_ast::ast::ModuleExportName;
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, BindingPattern, CallExpression, Expression,
    ImportDeclaration, ImportDeclarationSpecifier, NewExpression, ObjectExpression, ObjectProperty,
    ObjectPropertyKind, Program, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk;
use oxc_span::{GetSpan, Span};

/// Maximum nesting depth when digesting an object-literal initializer.
const DIGEST_DEPTH_LIMIT: u8 = 4;

/// One `import`/`require` binding: `local` names `imported` (when a named
/// import) out of `module`; `imported` is `None` for namespace/default forms.
struct ImportBinding<'p> {
    local: &'p str,
    module: &'p str,
    imported: Option<&'p str>,
}

/// Pre-computed value shape, either digested from a variable initializer or
/// read live from an expression handed to a rule callback.
enum Fact {
    Bool(bool),
    Str(String),
    Num(f64),
    /// Member chain or constructor resolved to a normalized FQN.
    Fqn(String),
    StrArray(Vec<String>),
    New {
        fqn: String,
        /// `defaultMethodOptions.authorizationType` of a `RestApi` initializer.
        default_authorization: Option<String>,
    },
    /// Digested object literal: property key to fact.
    Object(Vec<(String, SpannedFact)>),
    Opaque,
}

/// A fact together with the span it was computed from (for reporting).
pub(crate) struct SpannedFact {
    span: Span,
    fact: Fact,
}

impl SpannedFact {
    fn opaque(span: Span) -> Self {
        Self {
            span,
            fact: Fact::Opaque,
        }
    }
}

/// A property value read through a [`PropsView`].
#[derive(Clone, Copy)]
pub(crate) enum ValueView<'a, 'p> {
    /// Live expression reachable from the current call site.
    Live(&'a Expression<'p>),
    /// Digest fact recorded for a variable-backed props object.
    Digested(&'a SpannedFact),
}

impl ValueView<'_, '_> {
    pub(crate) fn span(&self) -> Span {
        match self {
            ValueView::Live(expression) => expression.span(),
            ValueView::Digested(spanned) => spanned.span,
        }
    }
}

/// A props object read either live from the call site or from a digest.
#[derive(Clone, Copy)]
pub(crate) enum PropsView<'a, 'p> {
    Live(&'a ObjectExpression<'p>),
    Digested(&'a [(String, SpannedFact)]),
}

/// File-local resolution state shared by every aws-cdk check.
pub(crate) struct CdkFile<'p> {
    imports: Vec<ImportBinding<'p>>,
    writes: Vec<(&'p str, BindingFact)>,
    object_digests: Vec<Vec<(String, SpannedFact)>>,
}

/// Fact recorded for one uniquely-declared binding.
enum BindingFact {
    Value(SpannedFact),
    /// Index into [`CdkFile::object_digests`] for object-literal inits.
    ObjectDigest(usize),
}

impl<'p> CdkFile<'p> {
    /// Cheap first stage: collects only the import table, which already
    /// answers whether the file touches CDK at all.
    pub(crate) fn collect_imports(program: &'p Program<'p>) -> Self {
        let mut import_pass = ImportPass::default();
        import_pass.visit_program(program);
        Self {
            imports: import_pass.imports,
            writes: Vec::new(),
            object_digests: Vec::new(),
        }
    }

    /// Whether any import/`require` binding roots in `aws-cdk-lib` or an
    /// `@aws-cdk/*` package. Every check's FQN resolution can only root in
    /// these modules, so a file without them can never produce findings.
    pub(crate) fn uses_cdk(&self) -> bool {
        self.imports.iter().any(|binding| {
            binding.module == "aws-cdk-lib"
                || binding.module.starts_with("aws-cdk-lib/")
                || binding.module.starts_with("@aws-cdk/")
        })
    }

    /// Expensive second stage: runs the write-fact pass plus the uniqueness
    /// sweep; callers should gate on [`Self::uses_cdk`] first.
    pub(crate) fn build(self, program: &'p Program<'p>) -> Self {
        let mut fact_pass = WriteFactPass { file: self };
        fact_pass.visit_program(program);
        let mut file = fact_pass.file;
        // Only bindings declared exactly once resolve uniquely, mirroring the
        // upstream scope check that bails out on multiple definitions.
        let unique: Vec<bool> = file
            .writes
            .iter()
            .map(|(name, _)| {
                file.writes
                    .iter()
                    .filter(|(other, _)| other == name)
                    .count()
                    == 1
            })
            .collect();
        let candidates = std::mem::take(&mut file.writes);
        for (candidate, is_unique) in candidates.into_iter().zip(unique) {
            if is_unique {
                file.writes.push(candidate);
            }
        }
        file
    }

    /// Dash-normalized fully-qualified name of `expression`, when provable.
    pub(crate) fn fqn(&self, expression: &Expression<'p>) -> Option<String> {
        Some(normalize_fqn(&self.raw_fqn(expression)?))
    }

    /// Whether `expression` resolves to the normalized CDK symbol `expected`.
    pub(crate) fn is_cdk(&self, expression: &Expression<'p>, expected: &str) -> bool {
        self.fqn(expression).is_some_and(|fqn| fqn == expected)
    }

    /// Classifies the props argument at `position` of a construct call. A
    /// direct object literal is [`PropsArg::Live`]; an identifier bound to a
    /// digested object literal is [`PropsArg::Digested`].
    pub(crate) fn props_arg<'a>(
        &'a self,
        arguments: &'a [Argument<'p>],
        position: usize,
    ) -> PropsArg<'a, 'p> {
        let Some(argument) = arguments.get(position) else {
            return PropsArg::Absent;
        };
        let Some(expression) = argument.as_expression() else {
            return PropsArg::Opaque;
        };
        match unparenthesized(expression) {
            Expression::ObjectExpression(object) => PropsArg::Live(object),
            Expression::Identifier(identifier) if identifier.name.as_str() == "undefined" => {
                PropsArg::Undefined
            }
            Expression::Identifier(identifier) => match self.write_fact(identifier.name.as_str()) {
                Some(BindingFact::ObjectDigest(index)) => {
                    PropsArg::Digested(&self.object_digests[*index])
                }
                _ => PropsArg::Opaque,
            },
            _ => PropsArg::Opaque,
        }
    }

    /// Boolean value of `view`.
    pub(crate) fn value_bool(&self, view: &ValueView<'_, 'p>) -> Option<bool> {
        match view {
            ValueView::Live(expression) => match unparenthesized(expression) {
                Expression::BooleanLiteral(literal) => Some(literal.value),
                Expression::Identifier(identifier) => self
                    .write_fact(identifier.name.as_str())
                    .and_then(BindingFact::bool),
                _ => None,
            },
            ValueView::Digested(spanned) => match &spanned.fact {
                Fact::Bool(value) => Some(*value),
                _ => None,
            },
        }
    }

    /// String value of `view`.
    pub(crate) fn value_str<'a>(&'a self, view: &'a ValueView<'_, 'p>) -> Option<&'a str> {
        match view {
            ValueView::Live(expression) => self.expression_str(expression),
            ValueView::Digested(spanned) => match &spanned.fact {
                Fact::Str(value) => Some(value),
                _ => None,
            },
        }
    }

    /// Numeric value of `view`.
    pub(crate) fn value_number(&self, view: &ValueView<'_, 'p>) -> Option<f64> {
        match view {
            ValueView::Live(expression) => match unparenthesized(expression) {
                Expression::NumericLiteral(literal) => Some(literal.value),
                Expression::Identifier(identifier) => self
                    .write_fact(identifier.name.as_str())
                    .and_then(BindingFact::number),
                _ => None,
            },
            ValueView::Digested(spanned) => match &spanned.fact {
                Fact::Num(value) => Some(*value),
                _ => None,
            },
        }
    }

    /// FQN of `view`: a member chain/constructor read live, or a recorded
    /// `Fqn`/`New` fact.
    pub(crate) fn value_fqn(&self, view: &ValueView<'_, 'p>) -> Option<String> {
        match view {
            ValueView::Live(expression) => self.live_or_bound_fqn(expression),
            ValueView::Digested(spanned) => match &spanned.fact {
                Fact::Fqn(fqn) | Fact::New { fqn, .. } => Some(fqn.clone()),
                _ => None,
            },
        }
    }

    /// FQN of the constructed value of `view` (`New` fact or live `new`).
    pub(crate) fn value_new_fqn(&self, view: &ValueView<'_, 'p>) -> Option<String> {
        match view {
            ValueView::Live(expression) => match unparenthesized(expression) {
                Expression::NewExpression(new) => self.fqn(&new.callee),
                Expression::Identifier(identifier) => self
                    .write_fact(identifier.name.as_str())
                    .and_then(BindingFact::new_fqn),
                _ => None,
            },
            ValueView::Digested(spanned) => match &spanned.fact {
                Fact::New { fqn, .. } => Some(fqn.clone()),
                _ => None,
            },
        }
    }

    /// String literals of `view`: a single literal or an array of literals.
    pub(crate) fn value_strings<'a>(&'a self, view: &'a ValueView<'_, 'p>) -> Vec<&'a str> {
        match view {
            ValueView::Live(expression) => self.live_strings(expression),
            ValueView::Digested(spanned) => match &spanned.fact {
                Fact::Str(value) => vec![value],
                Fact::StrArray(values) => values.iter().map(String::as_str).collect(),
                _ => Vec::new(),
            },
        }
    }

    /// `defaultMethodOptions.authorizationType` of `view` when it constructs
    /// a `RestApi` (live or digested).
    pub(crate) fn rest_api_default_authorization(
        &self,
        view: &ValueView<'_, 'p>,
    ) -> Option<String> {
        match view {
            ValueView::Live(expression) => match unparenthesized(expression) {
                Expression::NewExpression(new) => default_authorization_of(self, new),
                Expression::Identifier(identifier) => self
                    .write_fact(identifier.name.as_str())
                    .and_then(BindingFact::default_authorization),
                _ => None,
            },
            ValueView::Digested(spanned) => match &spanned.fact {
                Fact::New {
                    default_authorization,
                    ..
                } => default_authorization.clone(),
                _ => None,
            },
        }
    }

    fn live_or_bound_fqn(&self, expression: &Expression<'p>) -> Option<String> {
        match unparenthesized(expression) {
            Expression::Identifier(identifier) => {
                let name = identifier.name.as_str();
                self.write_fact(name)
                    .and_then(BindingFact::fqn)
                    .or_else(|| self.raw_fqn(expression).map(|fqn| normalize_fqn(&fqn)))
            }
            _ => self.raw_fqn(expression).map(|fqn| normalize_fqn(&fqn)),
        }
    }

    fn live_strings<'a>(&'a self, expression: &'a Expression<'p>) -> Vec<&'a str> {
        match unparenthesized(expression) {
            Expression::StringLiteral(literal) => vec![literal.value.as_str()],
            Expression::ArrayExpression(array) => array
                .elements
                .iter()
                .filter_map(ArrayExpressionElement::as_expression)
                .filter_map(|element| self.expression_str(element))
                .collect(),
            Expression::Identifier(identifier) => self
                .write_fact(identifier.name.as_str())
                .map(BindingFact::strings)
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn expression_str<'a>(&'a self, expression: &'a Expression<'p>) -> Option<&'a str> {
        match unparenthesized(expression) {
            Expression::StringLiteral(literal) => Some(literal.value.as_str()),
            Expression::Identifier(identifier) => self
                .write_fact(identifier.name.as_str())
                .and_then(BindingFact::str),
            _ => None,
        }
    }

    /// Whether `local` is uniquely bound to a constructor call whose callee
    /// resolves to the normalized symbol `expected`.
    pub(crate) fn bound_new_is_cdk(&self, local: &str, expected: &str) -> bool {
        self.write_fact(local)
            .and_then(BindingFact::new_fqn)
            .is_some_and(|fqn| fqn == expected)
    }

    fn write_fact(&self, local: &str) -> Option<&BindingFact> {
        self.writes
            .iter()
            .find(|(name, _)| *name == local)
            .map(|(_, fact)| fact)
    }

    /// Reduces `expression` to a dotted FQN: member-chain properties collect
    /// right-to-left, then the root identifier resolves through its import
    /// binding or unique-write fact. `require('module')` roots contribute the
    /// module path.
    fn raw_fqn(&self, expression: &Expression<'p>) -> Option<String> {
        let mut qualifiers: Vec<&str> = Vec::new();
        let mut current = unparenthesized(expression);
        loop {
            match current {
                Expression::StaticMemberExpression(member) => {
                    qualifiers.push(member.property.name.as_str());
                    current = unparenthesized(&member.object);
                }
                Expression::ComputedMemberExpression(member) => {
                    let Expression::StringLiteral(key) = unparenthesized(&member.expression) else {
                        return None;
                    };
                    qualifiers.push(key.value.as_str());
                    current = unparenthesized(&member.object);
                }
                Expression::CallExpression(call) => {
                    if let Some(module) = require_module(call) {
                        let mut parts: Vec<&str> = module.split('/').collect();
                        parts.extend(qualifiers.iter().rev().copied());
                        return Some(parts.join("."));
                    }
                    current = unparenthesized(&call.callee);
                }
                Expression::NewExpression(new) => current = unparenthesized(&new.callee),
                Expression::Identifier(identifier) => {
                    let name = identifier.name.as_str();
                    if let Some(binding) = self.imports.iter().find(|binding| binding.local == name)
                    {
                        let mut parts: Vec<&str> = binding.module.split('/').collect();
                        if let Some(imported) = binding.imported {
                            parts.push(imported);
                        }
                        parts.extend(qualifiers.iter().rev().copied());
                        return Some(parts.join("."));
                    }
                    return match self.write_fact(name) {
                        Some(fact) if qualifiers.is_empty() => fact.fqn(),
                        _ => None,
                    };
                }
                _ => return None,
            }
        }
    }
}

/// Elements of `view` when it is an array, as value views.
pub(crate) fn value_elements<'a, 'p>(view: ValueView<'a, 'p>) -> Vec<ValueView<'a, 'p>> {
    match view {
        ValueView::Live(expression) => match unparenthesized(expression) {
            Expression::ArrayExpression(array) => array
                .elements
                .iter()
                .filter_map(ArrayExpressionElement::as_expression)
                .map(ValueView::Live)
                .collect(),
            _ => Vec::new(),
        },
        ValueView::Digested(_) => Vec::new(),
    }
}

/// Span of the first string literal equal to `needle` within `view`
/// (the view itself for a single literal, an element for arrays).
pub(crate) fn wildcard_span(view: &ValueView<'_, '_>, needle: &str) -> Option<Span> {
    match view {
        ValueView::Live(expression) => match unparenthesized(expression) {
            Expression::StringLiteral(literal) => {
                (literal.value.as_str() == needle).then(|| literal.span())
            }
            Expression::ArrayExpression(array) => array
                .elements
                .iter()
                .filter_map(ArrayExpressionElement::as_expression)
                .find_map(|element| match unparenthesized(element) {
                    Expression::StringLiteral(literal) if literal.value.as_str() == needle => {
                        Some(literal.span())
                    }
                    _ => None,
                }),
            _ => None,
        },
        ValueView::Digested(spanned) => match &spanned.fact {
            Fact::Str(value) if value == needle => Some(spanned.span),
            Fact::StrArray(values) if values.iter().any(|value| value == needle) => {
                Some(spanned.span)
            }
            _ => None,
        },
    }
}

/// Property `key` of `props`, live or digested.
pub(crate) fn property_value<'v, 'p>(
    props: PropsView<'v, 'p>,
    key: &str,
) -> Option<ValueView<'v, 'p>> {
    match props {
        PropsView::Live(object) => {
            property_of(object, key).map(|property| ValueView::Live(&property.value))
        }
        PropsView::Digested(digest) => digest
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, spanned)| ValueView::Digested(spanned)),
    }
}

/// Object value of `view`, live or digested, for nested prop descent.
pub(crate) fn value_object<'a, 'p>(view: ValueView<'a, 'p>) -> Option<PropsView<'a, 'p>> {
    match view {
        ValueView::Live(expression) => match unparenthesized(expression) {
            Expression::ObjectExpression(object) => Some(PropsView::Live(object)),
            _ => None,
        },
        ValueView::Digested(spanned) => match &spanned.fact {
            Fact::Object(digest) => Some(PropsView::Digested(digest)),
            _ => None,
        },
    }
}

/// First non-computed property `key` of a live object literal.
pub(crate) fn property_of<'a, 'p>(
    object: &'a ObjectExpression<'p>,
    key: &str,
) -> Option<&'a ObjectProperty<'p>> {
    object.properties.iter().find_map(|property_kind| {
        let ObjectPropertyKind::ObjectProperty(property) = property_kind else {
            return None;
        };
        if property.computed {
            return None;
        }
        (property_key_name(&property.key) == Some(key)).then_some(property.as_ref())
    })
}

/// Resolution outcome of a construct props argument.
pub(crate) enum PropsArg<'a, 'p> {
    /// Direct object literal at the call site.
    Live(&'a ObjectExpression<'p>),
    /// Identifier bound to a digested object literal.
    Digested(&'a [(String, SpannedFact)]),
    /// No argument at the expected position.
    Absent,
    /// The literal `undefined`.
    Undefined,
    /// Present but unresolvable; conservative rules skip this shape.
    Opaque,
}

impl<'a, 'p> PropsArg<'a, 'p> {
    /// View for shapes a rule can inspect, `None` for absent/opaque ones.
    pub(crate) fn view(&self) -> Option<PropsView<'a, 'p>> {
        match self {
            PropsArg::Live(object) => Some(PropsView::Live(object)),
            PropsArg::Digested(digest) => Some(PropsView::Digested(digest)),
            PropsArg::Absent | PropsArg::Undefined | PropsArg::Opaque => None,
        }
    }

    /// Whether the props argument is provably missing (`Absent`/`undefined`).
    pub(crate) fn provably_absent(&self) -> bool {
        matches!(self, PropsArg::Absent | PropsArg::Undefined)
    }
}

impl BindingFact {
    fn bool(&self) -> Option<bool> {
        match self {
            BindingFact::Value(SpannedFact {
                fact: Fact::Bool(value),
                ..
            }) => Some(*value),
            _ => None,
        }
    }

    fn str(&self) -> Option<&str> {
        match self {
            BindingFact::Value(SpannedFact {
                fact: Fact::Str(value),
                ..
            }) => Some(value),
            _ => None,
        }
    }

    fn number(&self) -> Option<f64> {
        match self {
            BindingFact::Value(SpannedFact {
                fact: Fact::Num(value),
                ..
            }) => Some(*value),
            _ => None,
        }
    }

    fn fqn(&self) -> Option<String> {
        match self {
            BindingFact::Value(SpannedFact {
                fact: Fact::Fqn(fqn) | Fact::New { fqn, .. },
                ..
            }) => Some(fqn.clone()),
            _ => None,
        }
    }

    fn new_fqn(&self) -> Option<String> {
        match self {
            BindingFact::Value(SpannedFact {
                fact: Fact::New { fqn, .. },
                ..
            }) => Some(fqn.clone()),
            _ => None,
        }
    }

    fn default_authorization(&self) -> Option<String> {
        match self {
            BindingFact::Value(SpannedFact {
                fact:
                    Fact::New {
                        default_authorization,
                        ..
                    },
                ..
            }) => default_authorization.clone(),
            _ => None,
        }
    }

    fn strings(&self) -> Vec<&str> {
        match self {
            BindingFact::Value(SpannedFact {
                fact: Fact::Str(value),
                ..
            }) => vec![value],
            BindingFact::Value(SpannedFact {
                fact: Fact::StrArray(values),
                ..
            }) => values.iter().map(String::as_str).collect(),
            _ => Vec::new(),
        }
    }
}

/// Imported name of a specifier, unless it is a string literal.
fn import_name<'p>(name: &ModuleExportName<'p>) -> Option<&'p str> {
    match name {
        ModuleExportName::IdentifierName(identifier) => Some(identifier.name.as_str()),
        ModuleExportName::IdentifierReference(identifier) => Some(identifier.name.as_str()),
        ModuleExportName::StringLiteral(_) => None,
    }
}

fn normalize_fqn(fqn: &str) -> String {
    fqn.replace('-', "_")
}

/// Shared shape for "construct requires prop `key`" checks: reports
/// `omitted` when the props argument is provably without the key (absent,
/// `undefined`, or a provable object literal lacking it) and returns the
/// property value otherwise; `None` when there is nothing left to check.
pub(crate) fn required_prop<'a, 'p>(
    file: &'a CdkFile<'p>,
    new_expression: &'a NewExpression<'p>,
    position: usize,
    key: &str,
    rule: &str,
    omitted: &str,
    sink: &mut IssueSink<'_>,
) -> Option<ValueView<'a, 'p>> {
    let props = file.props_arg(&new_expression.arguments, position);
    if props.provably_absent() {
        sink.emit_span(RuleScope::Both, rule, omitted, new_expression.callee.span());
        return None;
    }
    let view = props.view()?;
    if let Some(value) = property_value(view, key) {
        Some(value)
    } else {
        sink.emit_span(RuleScope::Both, rule, omitted, new_expression.callee.span());
        None
    }
}

/// Description of a required-boolean-prop check.
#[derive(Clone, Copy)]
pub(crate) struct BoolPropCheck {
    pub(crate) key: &'static str,
    pub(crate) rule: &'static str,
    pub(crate) omitted: &'static str,
    pub(crate) disabled: &'static str,
}

/// `required_prop` plus the literal-`false` value report.
pub(crate) fn required_bool_prop(
    file: &CdkFile<'_>,
    new_expression: &NewExpression<'_>,
    position: usize,
    check: BoolPropCheck,
    sink: &mut IssueSink<'_>,
) {
    if let Some(value) = required_prop(
        file,
        new_expression,
        position,
        check.key,
        check.rule,
        check.omitted,
        sink,
    ) && file.value_bool(&value) == Some(false)
    {
        sink.emit_span(RuleScope::Both, check.rule, check.disabled, value.span());
    }
}

fn require_module<'a>(call: &CallExpression<'a>) -> Option<&'a str> {
    let Expression::Identifier(identifier) = unparenthesized(&call.callee) else {
        return None;
    };
    if identifier.name.as_str() != "require" || call.arguments.len() != 1 {
        return None;
    }
    let argument = call.arguments[0].as_expression()?;
    match unparenthesized(argument) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

fn require_module_of<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    let Expression::CallExpression(call) = unparenthesized(expression) else {
        return None;
    };
    require_module(call)
}

/// `defaultMethodOptions.authorizationType` of a `new RestApi(...)` site.
fn default_authorization_of(file: &CdkFile<'_>, new: &NewExpression<'_>) -> Option<String> {
    if !file.is_cdk(&new.callee, "aws_cdk_lib.aws_apigateway.RestApi") {
        return None;
    }
    let PropsArg::Live(props) = file.props_arg(&new.arguments, 2) else {
        return None;
    };
    let defaults = property_of(props, "defaultMethodOptions")?;
    let Expression::ObjectExpression(defaults) = unparenthesized(&defaults.value) else {
        return None;
    };
    let authorization = property_of(defaults, "authorizationType")?;
    file.value_str(&ValueView::Live(&authorization.value))
        .map(str::to_owned)
        .or_else(|| file.value_fqn(&ValueView::Live(&authorization.value)))
}

/// Pass 1: import declarations and `require` bindings.
#[derive(Default)]
struct ImportPass<'p> {
    imports: Vec<ImportBinding<'p>>,
}

impl<'p> Visit<'p> for ImportPass<'p> {
    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'p>) {
        let module = declaration.source.value.as_str();
        for specifier in declaration.specifiers.as_deref().into_iter().flatten() {
            self.imports.push(match specifier {
                ImportDeclarationSpecifier::ImportSpecifier(specifier) => ImportBinding {
                    local: specifier.local.name.as_str(),
                    module,
                    imported: import_name(&specifier.imported),
                },
                ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => ImportBinding {
                    local: specifier.local.name.as_str(),
                    module,
                    imported: None,
                },
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => ImportBinding {
                    local: specifier.local.name.as_str(),
                    module,
                    imported: None,
                },
            });
        }
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'p>) {
        let Some(init) = declarator.init.as_ref() else {
            return;
        };
        if let (BindingPattern::BindingIdentifier(identifier), Some(module)) =
            (&declarator.id, require_module_of(init))
        {
            self.imports.push(ImportBinding {
                local: identifier.name.as_str(),
                module,
                imported: None,
            });
        }
    }
}

/// Pass 2: digests the initializer of every uniquely-declared binding.
struct WriteFactPass<'p> {
    file: CdkFile<'p>,
}

impl<'p> WriteFactPass<'p> {
    /// Digests one expression into a spanned fact; depth-limited, opaque for
    /// anything not statically decidable.
    fn digest(&self, expression: &Expression<'p>, depth: u8) -> SpannedFact {
        let span = expression.span();
        if depth > DIGEST_DEPTH_LIMIT {
            return SpannedFact::opaque(span);
        }
        let fact = match unparenthesized(expression) {
            Expression::BooleanLiteral(literal) => Fact::Bool(literal.value),
            Expression::StringLiteral(literal) => Fact::Str(literal.value.as_str().to_owned()),
            Expression::NumericLiteral(literal) => Fact::Num(literal.value),
            Expression::ArrayExpression(array) => {
                let mut values = Vec::new();
                for element in &array.elements {
                    if let Some(Expression::StringLiteral(literal)) = element
                        .as_expression()
                        .map(|element| unparenthesized(element))
                    {
                        values.push(literal.value.as_str().to_owned());
                    } else {
                        values.clear();
                        break;
                    }
                }
                if values.len() == array.elements.len() && !array.elements.is_empty() {
                    Fact::StrArray(values)
                } else {
                    Fact::Opaque
                }
            }
            Expression::ObjectExpression(object) => {
                Fact::Object(self.digest_object(object, depth + 1))
            }
            Expression::NewExpression(new) => Fact::New {
                fqn: self.file.fqn(&new.callee).unwrap_or_default(),
                default_authorization: default_authorization_of(&self.file, new),
            },
            Expression::Identifier(_) | Expression::StaticMemberExpression(_) => {
                match self.file.fqn(expression) {
                    Some(fqn) => Fact::Fqn(fqn),
                    None => Fact::Opaque,
                }
            }
            _ => Fact::Opaque,
        };
        SpannedFact { span, fact }
    }

    fn digest_object(
        &self,
        object: &ObjectExpression<'p>,
        depth: u8,
    ) -> Vec<(String, SpannedFact)> {
        let mut digest = Vec::new();
        for property_kind in &object.properties {
            let ObjectPropertyKind::ObjectProperty(property) = property_kind else {
                continue;
            };
            if property.computed {
                continue;
            }
            let Some(key) = property_key_name(&property.key) else {
                continue;
            };
            digest.push((key.to_owned(), self.digest(&property.value, depth)));
        }
        digest
    }
}

impl<'p> Visit<'p> for WriteFactPass<'p> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'p>) {
        if let (BindingPattern::BindingIdentifier(identifier), Some(init)) =
            (&declarator.id, declarator.init.as_ref())
            && require_module_of(init).is_none()
        {
            let spanned = self.digest(init, 0);
            let fact = match spanned.fact {
                Fact::Object(digest) => {
                    self.file.object_digests.push(digest);
                    BindingFact::ObjectDigest(self.file.object_digests.len() - 1)
                }
                fact => BindingFact::Value(SpannedFact {
                    span: spanned.span,
                    fact,
                }),
            };
            self.file.writes.push((identifier.name.as_str(), fact));
        }
    }
}

/// Property-naming style of one IAM policy statement shape.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyStyle {
    /// CDK construct props (`effect`, `actions`, `resources`, `principals`).
    Cdk,
    /// Raw IAM JSON (`Effect`, `Action`, `Resource`, `Principal`).
    Json,
}

impl PolicyStyle {
    /// Statement property keys in this style: effect, actions, resources,
    /// principals.
    pub(crate) fn keys(self) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            PolicyStyle::Cdk => ("effect", "actions", "resources", "principals"),
            PolicyStyle::Json => ("Effect", "Action", "Resource", "Principal"),
        }
    }

    /// Whether `value` is the statement's allow effect in this style.
    pub(crate) fn is_allow(self, file: &CdkFile<'_>, value: &ValueView<'_, '_>) -> bool {
        match self {
            PolicyStyle::Cdk => file
                .value_fqn(value)
                .is_some_and(|fqn| fqn == "aws_cdk_lib.aws_iam.Effect.ALLOW"),
            PolicyStyle::Json => file.value_str(value) == Some("Allow"),
        }
    }
}

/// Effect property state of one statement view.
pub(crate) enum EffectState {
    /// The `effect` property is provably absent.
    Missing,
    /// Present and provably `ALLOW`/`"Allow"`.
    Allow,
    /// Present with any other value.
    Other,
}

/// Reads the `effect` property of one statement view.
pub(crate) fn policy_effect(
    file: &CdkFile<'_>,
    style: PolicyStyle,
    view: &PropsView<'_, '_>,
) -> EffectState {
    let (effect_key, ..) = style.keys();
    match property_value(*view, effect_key) {
        None => EffectState::Missing,
        Some(value) => {
            if style.is_allow(file, &value) {
                EffectState::Allow
            } else {
                EffectState::Other
            }
        }
    }
}

/// Policy statement views reachable from a `new iam.PolicyStatement` site.
pub(crate) fn policy_statements_new<'a, 'p>(
    file: &'a CdkFile<'p>,
    new: &'a NewExpression<'p>,
) -> Vec<(PolicyStyle, PropsView<'a, 'p>)> {
    if !file.is_cdk(&new.callee, "aws_cdk_lib.aws_iam.PolicyStatement") {
        return Vec::new();
    }
    file.props_arg(&new.arguments, 0)
        .view()
        .map(|view| vec![(PolicyStyle::Cdk, view)])
        .unwrap_or_default()
}

/// Policy statement views reachable from a policy call site
/// (`PolicyStatement.fromJson`, `PolicyDocument.fromJson` with its
/// `Statement` array).
pub(crate) fn policy_statements_call<'a, 'p>(
    file: &'a CdkFile<'p>,
    call: &'a CallExpression<'p>,
) -> Vec<(PolicyStyle, PropsView<'a, 'p>)> {
    let fqn = file.fqn(&call.callee);
    if fqn.as_deref() == Some("aws_cdk_lib.aws_iam.PolicyStatement.fromJson") {
        return file
            .props_arg(&call.arguments, 0)
            .view()
            .map(|view| vec![(PolicyStyle::Json, view)])
            .unwrap_or_default();
    }
    if fqn.as_deref() != Some("aws_cdk_lib.aws_iam.PolicyDocument.fromJson") {
        return Vec::new();
    }
    let Some(view) = file.props_arg(&call.arguments, 0).view() else {
        return Vec::new();
    };
    property_value(view, "Statement")
        .map(|statements| {
            value_elements(statements)
                .iter()
                .filter_map(|element| match element {
                    ValueView::Live(expression) => match unparenthesized(expression) {
                        Expression::ObjectExpression(object) => {
                            Some((PolicyStyle::Json, PropsView::Live(object)))
                        }
                        _ => None,
                    },
                    ValueView::Digested(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Inline rule driver: visits every construct/call site and dispatches to the
/// family checks with the shared resolution state.
pub(crate) struct RulePass<'a, 'i, 'p> {
    pub(crate) file: &'a CdkFile<'p>,
    pub(crate) sink: &'a mut IssueSink<'i>,
}

impl<'p> Visit<'p> for RulePass<'_, '_, 'p> {
    fn visit_new_expression(&mut self, expression: &NewExpression<'p>) {
        super::dispatch_new(self.file, expression, self.sink);
        walk::walk_new_expression(self, expression);
    }

    fn visit_call_expression(&mut self, expression: &CallExpression<'p>) {
        super::dispatch_call(self.file, expression, self.sink);
        walk::walk_call_expression(self, expression);
    }
}
