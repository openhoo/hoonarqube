// Shared test-assertion extraction and constant evaluation (generated).
//
// Single-file subset of the SonarJS `helpers/assertions.js` +
// `S5914/constant-evaluation.js` machinery shared by `javascript:S5914` /
// `typescript:S5914` (no-trivial-assertions) and `javascript:S1244` /
// `typescript:S1244` (no-floating-point-equality). The extraction mirrors
// `extractTestAssertion`: jest-like (`vitest`, `bun:test`, `@jest/globals`,
// `jest`), jasmine, Playwright (`@playwright/test`), chai (assert/expect/
// should styles), and node:assert. Framework availability is decided by
// file-local imports only: `import`/`require`/`import()` module names are
// collected like `getCurrentFileImports`, and the reference's
// package.json dependency fallback is treated as unavailable, so chai
// globals require a chai import in the same file. Cypress `cy.*.should()`
// chains are outside the subset.
//
// `resolve_constant` mirrors `resolveConstantPrimitiveValue`: literals,
// expression-free template literals, `!`/`+`/`-`/`typeof`/`void` unary
// expressions, the reference's binary/logical operator table, and `const`
// bindings resolved through the semantic model with the same visited-set
// cycle guard and same-execution-context TDZ check.

use crate::support::unparenthesized;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, BindingPattern, CallExpression, Expression, IdentifierReference, LogicalOperator,
    ModuleExportName, VariableDeclarationKind,
};
use oxc_semantic::{AstNode, Semantic};
use oxc_span::{GetSpan, Span};
use oxc_syntax::node::NodeId;
use oxc_syntax::scope::ScopeFlags;
use oxc_syntax::symbol::SymbolId;
use std::collections::HashSet;

/// Truthiness/nullishness predicate asserted on one value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Predicate {
    Truthy,
    Falsy,
    True,
    False,
    Defined,
    Undefined,
    Null,
    Exists,
}

/// Comparison kind of a two-sided assertion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Comparison {
    Strict,
    Loose,
    Deep,
}

/// Assertion library a construct was attributed to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AssertionStyle {
    JestLike,
    Jasmine,
    ChaiBdd,
    ChaiAssert,
    Playwright,
    NodeAssert,
}

/// Cross-framework assertion model (the reference `Assertion` union).
#[derive(Clone, Copy, Debug)]
pub(crate) enum AssertionKind<'a> {
    Predicate {
        predicate: Predicate,
        actual: &'a Expression<'a>,
    },
    Comparison {
        comparison: Comparison,
        actual: &'a Expression<'a>,
        expected: &'a Expression<'a>,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Assertion<'a> {
    pub(crate) style: AssertionStyle,
    pub(crate) kind: AssertionKind<'a>,
    pub(crate) negated: bool,
    /// Node the reference reports for this construct (matcher property or
    /// callee); used by S1244's comparison report.
    pub(crate) report_span: Span,
}

/// Modules imported by this file, mirroring `getCurrentFileImports`:
/// `import` sources plus `require('m')`/`require('m').x` and
/// `import('m')`/`await import('m')` variable initializers.
pub(crate) fn collect_file_imports(semantic: &Semantic<'_>) -> HashSet<String> {
    let mut imports = HashSet::new();
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::ImportDeclaration(declaration) => {
                imports.insert(declaration.source.value.to_string());
            }
            AstKind::VariableDeclarator(declarator) => {
                if let Some(init) = declarator.init.as_ref() {
                    if let Some(name) = require_or_import_module(init) {
                        imports.insert(name);
                    }
                }
            }
            _ => {}
        }
    }
    imports
}

/// `getRequireModuleName` ∪ `getDynamicImportModuleName` for one initializer.
fn require_or_import_module(expression: &Expression<'_>) -> Option<String> {
    match unparenthesized(expression) {
        Expression::CallExpression(call) => {
            require_module_name(call).or_else(|| member_require_module_name(&call.callee))
        }
        Expression::ImportExpression(import) => string_literal(&import.source),
        Expression::AwaitExpression(await_expression) => {
            match unparenthesized(&await_expression.argument) {
                Expression::ImportExpression(import) => string_literal(&import.source),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `require('m')` → `m`; `require` must be a bare identifier with one
/// string-literal argument.
fn require_module_name(call: &CallExpression<'_>) -> Option<String> {
    let Expression::Identifier(callee) = unparenthesized(&call.callee) else {
        return None;
    };
    if callee.name != "require" || call.arguments.len() != 1 {
        return None;
    }
    call.arguments[0].as_expression().and_then(string_literal)
}

/// `require('m').x` → `m` (the `getRequireCall` member-object arm).
fn member_require_module_name(expression: &Expression<'_>) -> Option<String> {
    let member = match unparenthesized(expression) {
        Expression::StaticMemberExpression(member) => &member.object,
        Expression::ComputedMemberExpression(member) => &member.object,
        _ => return None,
    };
    match unparenthesized(member) {
        Expression::CallExpression(call) => require_module_name(call),
        _ => None,
    }
}

fn string_literal(expression: &Expression<'_>) -> Option<String> {
    match unparenthesized(expression) {
        Expression::StringLiteral(literal) => Some(literal.value.to_string()),
        _ => None,
    }
}

fn argument_at<'a>(call: &'a CallExpression<'a>, index: usize) -> Option<&'a Expression<'a>> {
    call.arguments.get(index).and_then(Argument::as_expression)
}

/// The callee's non-computed, non-optional static member (`obj.method()`).
fn method_member<'a, 'b>(
    call: &'b CallExpression<'a>,
) -> Option<&'b oxc_ast::ast::StaticMemberExpression<'a>> {
    match unparenthesized(&call.callee) {
        Expression::StaticMemberExpression(member) if !member.optional => Some(member),
        _ => None,
    }
}

fn identifier_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
        _ => None,
    }
}

/// `extractTestAssertion` for one `CallExpression` or `MemberExpression`
/// node. `imports` comes from [`collect_file_imports`]; the reference's
/// dependency-manifest fallback is unavailable in single-file analysis, so
/// chai globals additionally require a chai import.
pub(crate) fn extract_test_assertion<'a>(
    semantic: &'a Semantic<'a>,
    node: &AstNode<'a>,
    imports: &HashSet<String>,
) -> Option<Assertion<'a>> {
    match node.kind() {
        AstKind::CallExpression(call) => extract_call_assertion(semantic, node, call, imports),
        AstKind::StaticMemberExpression(member) => {
            extract_chai_property_assertion(semantic, member, imports)
        }
        _ => None,
    }
}

const JEST_LIKE_MODULES: [&str; 4] = ["vitest", "bun:test", "@jest/globals", "jest"];
const JASMINE_MODULES: [&str; 4] = ["jasmine", "jasmine-core", "jasmine-node", "karma-jasmine"];
const PLAYWRIGHT_MODULES: [&str; 1] = ["@playwright/test"];
const CHAI_MODULES: [&str; 5] = [
    "chai",
    "chai/register-assert",
    "chai/register-expect",
    "chai/register-should",
    "cypress",
];
const NODE_ASSERT_MODULES: [&str; 4] = [
    "assert",
    "node:assert",
    "assert/strict",
    "node:assert/strict",
];

fn any_import(imports: &HashSet<String>, modules: &[&str]) -> bool {
    modules.iter().any(|module| imports.contains(*module))
}

fn extract_call_assertion<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &'a CallExpression<'a>,
    imports: &HashSet<String>,
) -> Option<Assertion<'a>> {
    if any_import(imports, &JEST_LIKE_MODULES) {
        if let Some(assertion) = extract_expect_assertion(call, AssertionStyle::JestLike) {
            return Some(assertion);
        }
    }
    if any_import(imports, &JASMINE_MODULES) {
        if let Some(assertion) = extract_expect_assertion(call, AssertionStyle::Jasmine) {
            return Some(assertion);
        }
    }
    if any_import(imports, &PLAYWRIGHT_MODULES) {
        if let Some(assertion) = extract_expect_assertion(call, AssertionStyle::Playwright) {
            return Some(assertion);
        }
    }
    if any_import(imports, &CHAI_MODULES) {
        if let Some(assertion) = extract_chai_call_assertion(semantic, node, call) {
            return Some(assertion);
        }
    }
    if any_import(imports, &NODE_ASSERT_MODULES) {
        return extract_node_assertion(semantic, node, call);
    }
    None
}

/// Jest/Jasmine/Playwright `expect(x)[.not].matcher(...)` assertions.
fn extract_expect_assertion<'a>(
    call: &'a CallExpression<'a>,
    style: AssertionStyle,
) -> Option<Assertion<'a>> {
    let member = method_member(call)?;
    let (expect_call, negated) = extract_expect_chain(&member.object)?;
    let actual = argument_at(expect_call, 0)?;
    let matcher = member.property.name.as_str();
    if let Some(predicate) = jest_predicate(matcher) {
        if call.arguments.is_empty() {
            return Some(Assertion {
                style,
                kind: AssertionKind::Predicate { predicate, actual },
                negated,
                report_span: actual.span(),
            });
        }
    }
    let comparison = jest_comparison(matcher)?;
    if call.arguments.len() != 1 {
        return None;
    }
    let expected = argument_at(call, 0)?;
    Some(Assertion {
        style,
        kind: AssertionKind::Comparison {
            comparison,
            actual,
            expected,
        },
        negated,
        report_span: member.property.span(),
    })
}

fn jest_predicate(name: &str) -> Option<Predicate> {
    match name {
        "toBeTruthy" => Some(Predicate::Truthy),
        "toBeFalsy" => Some(Predicate::Falsy),
        "toBeDefined" => Some(Predicate::Defined),
        "toBeUndefined" => Some(Predicate::Undefined),
        "toBeNull" => Some(Predicate::Null),
        _ => None,
    }
}

fn jest_comparison(name: &str) -> Option<Comparison> {
    match name {
        "toBe" => Some(Comparison::Strict),
        "toEqual" | "toStrictEqual" => Some(Comparison::Deep),
        _ => None,
    }
}

/// `expect(x)` at the base of a `.not`-only member chain, like the
/// reference `extractExpectChain`.
fn extract_expect_chain<'a>(
    expression: &'a Expression<'a>,
) -> Option<(&'a CallExpression<'a>, bool)> {
    let mut current = expression;
    let mut negated = false;
    while let Expression::StaticMemberExpression(member) = unparenthesized(current) {
        if negated || member.property.name != "not" {
            return None;
        }
        negated = true;
        current = &member.object;
    }
    let Expression::CallExpression(expect_call) = unparenthesized(current) else {
        return None;
    };
    if expect_call.arguments.len() != 1 || identifier_name(&expect_call.callee) != Some("expect") {
        return None;
    }
    Some((expect_call, negated))
}

/// Chai assert/expect/should call assertions (chai imported in file).
fn extract_chai_call_assertion<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &'a CallExpression<'a>,
) -> Option<Assertion<'a>> {
    extract_chai_assert_assertion(semantic, node, call)
        .or_else(|| extract_chai_expect_call_assertion(semantic, node, call))
        .or_else(|| extract_chai_should_call_assertion(call))
}

/// `assert.method(...)` chai-assert style.
fn extract_chai_assert_assertion<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &'a CallExpression<'a>,
) -> Option<Assertion<'a>> {
    let (method, report_span) = chai_assert_call(semantic, node, call)?;
    if let Some((predicate, negated)) = chai_assert_predicate(&method) {
        let actual = argument_at(call, 0)?;
        return Some(Assertion {
            style: AssertionStyle::ChaiAssert,
            kind: AssertionKind::Predicate { predicate, actual },
            negated,
            report_span: actual.span(),
        });
    }
    let actual = argument_at(call, 0)?;
    let expected = argument_at(call, 1)?;
    Some(Assertion {
        style: AssertionStyle::ChaiAssert,
        kind: AssertionKind::Comparison {
            comparison: chai_assert_comparison(&method),
            actual,
            expected,
        },
        negated: method.starts_with("not"),
        report_span,
    })
}

/// The chai assert method invoked by `call`, plus the reference report
/// node (callee for FQN-resolved calls, property for `assert.m()`).
fn chai_assert_call<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &'a CallExpression<'a>,
) -> Option<(String, Span)> {
    if let Some(fqn) = fully_qualified_name(semantic, node, &call.callee) {
        if let Some(method) = fqn
            .strip_prefix("chai.assert")
            .and_then(|rest| rest.strip_prefix('.'))
        {
            let method = if method.is_empty() { "assert" } else { method };
            if let Some(name) = chai_assert_method_name(method) {
                return Some((name.to_string(), call.callee.span()));
            }
        }
    }
    if identifier_name(&call.callee) == Some("assert") && is_unbound(semantic, node, "assert") {
        return Some(("assert".to_string(), call.callee.span()));
    }
    let member = method_member(call)?;
    if identifier_name(&member.object) == Some("assert") && is_unbound(semantic, node, "assert") {
        if let Some(name) = chai_assert_method_name(member.property.name.as_str()) {
            return Some((name.to_string(), member.property.span()));
        }
    }
    None
}

fn chai_assert_method_name<'a>(name: &'a str) -> Option<&'a str> {
    match name {
        "assert" | "ok" | "isOk" | "isNotOk" | "isTrue" | "isFalse" | "isNull" | "isNotNull"
        | "isUndefined" | "isDefined" | "exists" | "notExists" | "equal" | "notEqual"
        | "strictEqual" | "notStrictEqual" | "deepEqual" | "notDeepEqual" => Some(name),
        _ => None,
    }
}

fn chai_assert_predicate(method: &str) -> Option<(Predicate, bool)> {
    match method {
        "assert" | "ok" | "isOk" => Some((Predicate::Truthy, false)),
        "isNotOk" => Some((Predicate::Truthy, true)),
        "isTrue" => Some((Predicate::True, false)),
        "isFalse" => Some((Predicate::False, false)),
        "isNull" => Some((Predicate::Null, false)),
        "isNotNull" => Some((Predicate::Null, true)),
        "isUndefined" => Some((Predicate::Undefined, false)),
        "isDefined" => Some((Predicate::Defined, false)),
        "exists" => Some((Predicate::Exists, false)),
        "notExists" => Some((Predicate::Exists, true)),
        _ => None,
    }
}

fn chai_assert_comparison(method: &str) -> Comparison {
    match method {
        "equal" | "notEqual" => Comparison::Loose,
        "deepEqual" | "notDeepEqual" => Comparison::Deep,
        _ => Comparison::Strict,
    }
}

/// `expect(x).to.equal(y)` / `expect(x).to.eql(y)` chai-bdd call style.
fn extract_chai_expect_call_assertion<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &'a CallExpression<'a>,
) -> Option<Assertion<'a>> {
    let member = method_member(call)?;
    let matcher = member.property.name.as_str();
    let comparison = chai_call_comparison(matcher, &member.object)?;
    let (actual, negated) = extract_chai_expect_chain(semantic, node, &member.object)?;
    let expected = argument_at(call, 0)?;
    Some(Assertion {
        style: AssertionStyle::ChaiBdd,
        kind: AssertionKind::Comparison {
            comparison,
            actual,
            expected,
        },
        negated,
        report_span: member.property.span(),
    })
}

/// `equal`/`equals`/`eq` (strict unless `.deep` in chain) and
/// `eql`/`eqls` (always deep).
fn chai_call_comparison(matcher: &str, chain: &Expression<'_>) -> Option<Comparison> {
    match matcher {
        "eql" | "eqls" => Some(Comparison::Deep),
        "equal" | "equals" | "eq" => {
            let (_, properties) = member_chain(chain)?;
            if properties.iter().any(|property| *property == "deep") {
                Some(Comparison::Deep)
            } else {
                Some(Comparison::Strict)
            }
        }
        _ => None,
    }
}

/// `expect(x)` at the base of a chai member chain; `negated` when `not`
/// appears among the chain properties.
fn extract_chai_expect_chain<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    expression: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, bool)> {
    let (base, properties) = member_chain(expression)?;
    let Expression::CallExpression(expect_call) = unparenthesized(base) else {
        return None;
    };
    if expect_call.arguments.is_empty() {
        return None;
    }
    let is_chai_expect = fully_qualified_name(semantic, node, &expect_call.callee).as_deref()
        == Some("chai.expect")
        || identifier_name(&expect_call.callee) == Some("expect");
    if !is_chai_expect {
        return None;
    }
    let actual = argument_at(expect_call, 0)?;
    Some((actual, properties.iter().any(|property| *property == "not")))
}

/// `value.should.equal(y)` chai-bdd call style.
fn extract_chai_should_call_assertion<'a>(call: &'a CallExpression<'a>) -> Option<Assertion<'a>> {
    let member = method_member(call)?;
    let matcher = member.property.name.as_str();
    let comparison = chai_call_comparison(matcher, &member.object)?;
    let (actual, negated) = extract_chai_should_chain(&member.object)?;
    let expected = argument_at(call, 0)?;
    Some(Assertion {
        style: AssertionStyle::ChaiBdd,
        kind: AssertionKind::Comparison {
            comparison,
            actual,
            expected,
        },
        negated,
        report_span: member.property.span(),
    })
}

/// Chai property assertions: `expect(x).to.be.ok` / `value.should.be.ok`.
pub(crate) fn extract_chai_property_assertion<'a>(
    semantic: &'a Semantic<'a>,
    member: &'a oxc_ast::ast::StaticMemberExpression<'a>,
    imports: &HashSet<String>,
) -> Option<Assertion<'a>> {
    if !any_import(imports, &CHAI_MODULES) {
        return None;
    }
    let (predicate, predicate_negated) = chai_property_predicate(member.property.name.as_str())?;
    // The member node itself is not the reference's `node` for scope
    // lookups; any node in the file works for `is_unbound`.
    let (actual, negated) =
        extract_chai_expect_chain(semantic, member_node(semantic, member), &member.object)
            .or_else(|| extract_chai_should_chain(&member.object))?;
    Some(Assertion {
        style: AssertionStyle::ChaiBdd,
        kind: AssertionKind::Predicate { predicate, actual },
        negated: negated != predicate_negated,
        report_span: actual.span(),
    })
}

/// The `AstNode` owning `member` (needed for scope-aware FQN lookups).
fn member_node<'a>(
    semantic: &'a Semantic<'a>,
    member: &'a oxc_ast::ast::StaticMemberExpression<'a>,
) -> &'a AstNode<'a> {
    semantic
        .nodes()
        .iter()
        .find(|node| node.kind().span() == member.span)
        .unwrap_or_else(|| semantic.nodes().get_node(NodeId::ROOT))
}

fn chai_property_predicate(name: &str) -> Option<(Predicate, bool)> {
    match name {
        "ok" => Some((Predicate::Truthy, false)),
        "true" => Some((Predicate::True, false)),
        "false" => Some((Predicate::False, false)),
        "null" => Some((Predicate::Null, false)),
        "undefined" => Some((Predicate::Undefined, false)),
        "exist" | "exists" => Some((Predicate::Exists, false)),
        _ => None,
    }
}

/// `value.should[.not].predicate` chain: the actual expression and whether
/// `not` appears before `should`.
fn extract_chai_should_chain<'a>(
    expression: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, bool)> {
    let mut properties: Vec<&str> = Vec::new();
    let mut current = expression;
    while let Expression::StaticMemberExpression(member) = unparenthesized(current) {
        if member.property.name == "should" {
            return Some((
                &member.object,
                properties.iter().any(|property| *property == "not"),
            ));
        }
        properties.push(member.property.name.as_str());
        current = &member.object;
    }
    None
}

/// `extractMemberChain`: base expression plus property names in chain
/// order (leftmost first).
fn member_chain<'a>(expression: &'a Expression<'a>) -> Option<(&'a Expression<'a>, Vec<&'a str>)> {
    let mut properties: Vec<&str> = Vec::new();
    let mut current = expression;
    while let Expression::StaticMemberExpression(member) = unparenthesized(current) {
        properties.push(member.property.name.as_str());
        current = &member.object;
    }
    properties.reverse();
    Some((current, properties))
}

/// Node.js `assert`/`assert.strict` assertions (assert imported in file).
fn extract_node_assertion<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &'a CallExpression<'a>,
) -> Option<Assertion<'a>> {
    let (method, negated, report_span) = node_assert_call(semantic, node, call)?;
    if method == "assert" || method == "ok" {
        let actual = argument_at(call, 0)?;
        return Some(Assertion {
            style: AssertionStyle::NodeAssert,
            kind: AssertionKind::Predicate {
                predicate: Predicate::Truthy,
                actual,
            },
            negated: false,
            report_span: actual.span(),
        });
    }
    let actual = argument_at(call, 0)?;
    let expected = argument_at(call, 1)?;
    Some(Assertion {
        style: AssertionStyle::NodeAssert,
        kind: AssertionKind::Comparison {
            comparison: node_assert_comparison(method),
            actual,
            expected,
        },
        negated,
        report_span,
    })
}

fn node_assert_comparison(method: &str) -> Comparison {
    match method {
        "deepStrictEqual" | "notDeepStrictEqual" | "deepEqual" | "notDeepEqual" => Comparison::Deep,
        "looseDeepEqual" | "looseNotDeepEqual" => Comparison::Loose,
        _ => Comparison::Strict,
    }
}

/// `getNodeJSAssertCall`: FQN-resolved `assert.*` methods, then the
/// unqualified `assert.m()` fallback for untraceable `assert` objects.
fn node_assert_call<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &'a CallExpression<'a>,
) -> Option<(&'static str, bool, Span)> {
    if let Some(fqn) = fully_qualified_name(semantic, node, &call.callee) {
        if let Some(method) = node_assert_method_from_fqn(&fqn) {
            let strict = fqn.starts_with("assert.strict.");
            let normalized = normalize_node_assert_method(method, strict);
            return Some((normalized, method.starts_with("not"), call.callee.span()));
        }
    }
    let member = method_member(call)?;
    if identifier_name(&member.object) != Some("assert") {
        return None;
    }
    let method = node_assert_method_from_name(member.property.name.as_str())?;
    if method == "deepEqual" || method == "notDeepEqual" {
        return None;
    }
    let normalized = normalize_node_assert_method(method, false);
    Some((
        normalized,
        method.starts_with("not"),
        member.property.span(),
    ))
}

fn node_assert_method_from_fqn(fqn: &str) -> Option<&'static str> {
    match fqn {
        "assert" | "assert.strict" => Some("assert"),
        "assert.ok" | "assert.strict.ok" => Some("ok"),
        "assert.deepEqual" | "assert.strict.deepEqual" => Some("deepEqual"),
        "assert.notDeepEqual" | "assert.strict.notDeepEqual" => Some("notDeepEqual"),
        "assert.strictEqual" | "assert.strict.strictEqual" => Some("strictEqual"),
        "assert.notStrictEqual" | "assert.strict.notStrictEqual" => Some("notStrictEqual"),
        "assert.deepStrictEqual" | "assert.strict.deepStrictEqual" => Some("deepStrictEqual"),
        "assert.notDeepStrictEqual" | "assert.strict.notDeepStrictEqual" => {
            Some("notDeepStrictEqual")
        }
        _ => None,
    }
}

fn node_assert_method_from_name(name: &str) -> Option<&'static str> {
    match name {
        "ok" => Some("ok"),
        "deepEqual" => Some("deepEqual"),
        "notDeepEqual" => Some("notDeepEqual"),
        "strictEqual" => Some("strictEqual"),
        "notStrictEqual" => Some("notStrictEqual"),
        "deepStrictEqual" => Some("deepStrictEqual"),
        "notDeepStrictEqual" => Some("notDeepStrictEqual"),
        _ => None,
    }
}

fn normalize_node_assert_method(method: &'static str, strict: bool) -> &'static str {
    match (method, strict) {
        ("deepEqual", false) => "looseDeepEqual",
        ("notDeepEqual", false) => "looseNotDeepEqual",
        (other, _) => other,
    }
}

/// Whether `name` has no binding visible from `node`'s scope (the
/// reference's `defs.length === 0` global check).
fn is_unbound(semantic: &Semantic<'_>, node: &AstNode<'_>, name: &str) -> bool {
    semantic
        .scoping()
        .find_binding(node.scope_id(), name.into())
        .is_none()
}

/// Symbol an identifier reference resolves to; `None` for globals.
fn reference_symbol(
    semantic: &Semantic<'_>,
    identifier: &IdentifierReference<'_>,
) -> Option<SymbolId> {
    semantic
        .scoping()
        .get_reference(identifier.reference_id.get()?)
        .symbol_id()
}

/// Single-file subset of `getFullyQualifiedName`: member/call/tag/new
/// chains reduce to a base identifier whose import/require binding gives
/// the module qualifier. Unbound identifiers yield `None` (the reference
/// only returns bare names for eslint built-in globals, which are not
/// modeled here).
pub(crate) fn fully_qualified_name(
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    expression: &Expression<'_>,
) -> Option<String> {
    let mut qualifiers: Vec<String> = Vec::new();
    let base = reduce_to_identifier(expression, &mut qualifiers);
    let Expression::Identifier(identifier) = unparenthesized(base) else {
        // `require('m')(...)` / `require('m').x()` call tails.
        if let Expression::CallExpression(call) = unparenthesized(base) {
            let mut inner: Vec<String> = Vec::new();
            let callee_base = reduce_to_identifier(&call.callee, &mut inner);
            if let Expression::CallExpression(require_call) = unparenthesized(callee_base) {
                if let Some(module) = require_module_name(require_call) {
                    inner.insert(0, module);
                    return Some(inner.join("."));
                }
            }
        }
        return None;
    };
    let symbol = reference_symbol(semantic, identifier)?;
    binding_fqn(semantic, node, symbol, &mut qualifiers, 0)
}

/// `reduceToIdentifier`: unwrap member/call/tag/new/chain/TS-non-null
/// layers, collecting property qualifiers.
fn reduce_to_identifier<'a>(
    expression: &'a Expression<'a>,
    qualifiers: &mut Vec<String>,
) -> &'a Expression<'a> {
    let mut current = expression;
    loop {
        match unparenthesized(current) {
            Expression::StaticMemberExpression(member) => {
                qualifiers.insert(0, member.property.name.to_string());
                current = &member.object;
            }
            Expression::ComputedMemberExpression(member) => {
                if let Some(name) = string_literal(&member.expression) {
                    qualifiers.insert(0, name);
                }
                current = &member.object;
            }
            Expression::CallExpression(call) => {
                if require_module_name(call).is_some() {
                    return current;
                }
                current = &call.callee;
            }
            Expression::TaggedTemplateExpression(tagged) => current = &tagged.tag,
            Expression::NewExpression(new) => current = &new.callee,
            Expression::ChainExpression(chain) => {
                let Some(next) = chain_element_inner(&chain.expression, qualifiers) else {
                    return current;
                };
                current = next;
            }
            Expression::TSNonNullExpression(non_null) => current = &non_null.expression,
            _ => return current,
        }
    }
}

/// The expression a `ChainElement` reduces to, collecting member
/// qualifiers; `None` when the element cannot be reduced further.
fn chain_element_inner<'a>(
    element: &'a oxc_ast::ast::ChainElement<'a>,
    qualifiers: &mut Vec<String>,
) -> Option<&'a Expression<'a>> {
    match element {
        oxc_ast::ast::ChainElement::CallExpression(call) => Some(&call.callee),
        oxc_ast::ast::ChainElement::TSNonNullExpression(non_null) => Some(&non_null.expression),
        oxc_ast::ast::ChainElement::StaticMemberExpression(member) => {
            qualifiers.insert(0, member.property.name.to_string());
            Some(&member.object)
        }
        oxc_ast::ast::ChainElement::ComputedMemberExpression(member) => {
            if let Some(name) = string_literal(&member.expression) {
                qualifiers.insert(0, name);
            }
            Some(&member.object)
        }
        _ => None,
    }
}

/// FQN of a bound symbol: import bindings resolve to `module[.name]`,
/// variable bindings to their require/aliased initializer FQN.
fn binding_fqn(
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    symbol: SymbolId,
    qualifiers: &mut Vec<String>,
    depth: usize,
) -> Option<String> {
    if depth > 8 || semantic.scoping().symbol_declarations(symbol).count() != 1 {
        return None;
    }
    let declaration = semantic.symbol_declaration(symbol);
    match semantic.nodes().kind(declaration.id()) {
        AstKind::ImportSpecifier(specifier) => {
            if specifier.import_kind.is_type() {
                return None;
            }
            let source = import_source(semantic, declaration.id())?;
            if let ModuleExportName::IdentifierName(imported) = &specifier.imported {
                if imported.name != "default" {
                    qualifiers.insert(0, imported.name.to_string());
                }
            }
            Some(join_module_fqn(&source, qualifiers))
        }
        AstKind::ImportDefaultSpecifier(_) | AstKind::ImportNamespaceSpecifier(_) => {
            let source = import_source(semantic, declaration.id())?;
            Some(join_module_fqn(&source, qualifiers))
        }
        AstKind::VariableDeclarator(declarator) => {
            if let BindingPattern::ObjectPattern(pattern) = &declarator.id {
                push_object_pattern_qualifier(semantic, pattern, symbol, qualifiers);
            }
            let init = declarator.init.as_ref()?;
            expression_fqn(semantic, node, init, qualifiers, depth)
        }
        _ => None,
    }
}

/// The `ImportDeclaration` source string owning an import specifier node.
fn import_source(semantic: &Semantic<'_>, declaration: NodeId) -> Option<String> {
    let parent = semantic.nodes().parent_id(declaration);
    match semantic.nodes().kind(parent) {
        AstKind::ImportDeclaration(declaration) => Some(declaration.source.value.to_string()),
        _ => None,
    }
}

fn join_module_fqn(source: &str, qualifiers: &[String]) -> String {
    let mut parts: Vec<String> = source.split('/').map(str::to_string).collect();
    parts.extend(qualifiers.iter().cloned());
    strip_node_prefix(&parts.join(".")).to_string()
}

fn strip_node_prefix(fqn: &str) -> &str {
    fqn.strip_prefix("node:").unwrap_or(fqn)
}

/// `const {x: local} = require('m')`: unshift the property key whose value
/// binds `symbol`.
fn push_object_pattern_qualifier(
    semantic: &Semantic<'_>,
    pattern: &oxc_ast::ast::ObjectPattern<'_>,
    symbol: SymbolId,
    qualifiers: &mut Vec<String>,
) {
    for property in &pattern.properties {
        let bound = match &property.value {
            BindingPattern::BindingIdentifier(identifier) => identifier.symbol_id.get(),
            _ => None,
        };
        if bound == Some(symbol) {
            if let Some(name) = crate::support::property_key_name(&property.key) {
                qualifiers.insert(0, name.to_string());
            }
        }
    }
    let _ = semantic;
}

/// `expression_fqn`: `require('m')` → `m`, `require('m').x.y` → `m.x.y`,
/// `require('m')(...)` → `m`, a bound identifier → its binding's FQN,
/// member/call chains reduce through object/callee.
fn expression_fqn(
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    expression: &Expression<'_>,
    qualifiers: &mut Vec<String>,
    depth: usize,
) -> Option<String> {
    let mut inner: Vec<String> = Vec::new();
    let base = reduce_to_identifier(expression, &mut inner);
    match unparenthesized(base) {
        Expression::CallExpression(call) => {
            if let Some(module) = require_module_name(call) {
                inner.insert(0, module);
                qualifiers.splice(0..0, inner);
                return Some(strip_node_prefix(&qualifiers.join(".")).to_string());
            }
            None
        }
        Expression::Identifier(identifier) => {
            let symbol = reference_symbol(semantic, identifier)?;
            qualifiers.splice(0..0, inner);
            binding_fqn(semantic, node, symbol, qualifiers, depth + 1)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Constant evaluation (S5914 `constant-evaluation.js` subset)
// ---------------------------------------------------------------------

/// A statically known primitive value.
#[derive(Clone, Debug)]
pub(crate) enum ConstantValue {
    Null,
    Undefined,
    Boolean(bool),
    Number(f64),
    String(String),
    BigInt(i128),
}

impl ConstantValue {
    /// JavaScript truthiness.
    pub(crate) fn truthy(&self) -> bool {
        match self {
            Self::Null | Self::Undefined => false,
            Self::Boolean(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(value) => !value.is_empty(),
            Self::BigInt(value) => *value != 0,
        }
    }
}

/// `predicateHolds`: whether a constant satisfies an assertion predicate.
pub(crate) fn predicate_holds(predicate: Predicate, value: &ConstantValue) -> bool {
    match predicate {
        Predicate::Truthy => value.truthy(),
        Predicate::Falsy => !value.truthy(),
        Predicate::True => matches!(value, ConstantValue::Boolean(true)),
        Predicate::False => matches!(value, ConstantValue::Boolean(false)),
        Predicate::Defined => !matches!(value, ConstantValue::Undefined),
        Predicate::Undefined => matches!(value, ConstantValue::Undefined),
        Predicate::Null => matches!(value, ConstantValue::Null),
        Predicate::Exists => !matches!(value, ConstantValue::Null | ConstantValue::Undefined),
    }
}

/// `freshReferencePredicateHolds`: predicates over freshly-created
/// references (always truthy/defined/existing, never null/true/false).
pub(crate) fn fresh_reference_predicate_holds(predicate: Predicate) -> bool {
    match predicate {
        Predicate::Truthy | Predicate::Defined | Predicate::Exists => true,
        Predicate::Falsy
        | Predicate::True
        | Predicate::False
        | Predicate::Undefined
        | Predicate::Null => false,
    }
}

/// `isFreshReferenceExpression`: expressions creating a new reference on
/// each evaluation (object/array/function/class/new/regex literals).
pub(crate) fn is_fresh_reference_expression(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::ArrayExpression(_)
            | Expression::ObjectExpression(_)
            | Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_)
            | Expression::ClassExpression(_)
            | Expression::NewExpression(_)
            | Expression::RegExpLiteral(_)
    )
}

/// `strictEqualityHolds`: `Object.is` for jest-like/playwright/node-assert
/// strict matchers, `===` for jasmine/chai.
pub(crate) fn strict_equality_holds(
    style: AssertionStyle,
    actual: &ConstantValue,
    expected: &ConstantValue,
) -> bool {
    let object_is = matches!(
        style,
        AssertionStyle::JestLike | AssertionStyle::Playwright | AssertionStyle::NodeAssert
    );
    if object_is {
        same_value(actual, expected)
    } else {
        strict_equals(actual, expected)
    }
}

fn strict_equals(left: &ConstantValue, right: &ConstantValue) -> bool {
    match (left, right) {
        (ConstantValue::Null, ConstantValue::Null)
        | (ConstantValue::Undefined, ConstantValue::Undefined) => true,
        (ConstantValue::Boolean(a), ConstantValue::Boolean(b)) => a == b,
        (ConstantValue::Number(a), ConstantValue::Number(b)) => a == b,
        (ConstantValue::String(a), ConstantValue::String(b)) => a == b,
        (ConstantValue::BigInt(a), ConstantValue::BigInt(b)) => a == b,
        _ => false,
    }
}

fn same_value(left: &ConstantValue, right: &ConstantValue) -> bool {
    match (left, right) {
        (ConstantValue::Number(a), ConstantValue::Number(b)) => {
            if a.is_nan() && b.is_nan() {
                return true;
            }
            if *a == 0.0 && *b == 0.0 {
                return a.is_sign_negative() == b.is_sign_negative();
            }
            a == b
        }
        _ => strict_equals(left, right),
    }
}

/// `resolveConstantPrimitiveValue` over the oxc AST. Parentheses are
/// unwrapped at every step (the reference AST has no paren nodes).
pub(crate) fn resolve_constant<'a>(
    semantic: &Semantic<'a>,
    expression: &'a Expression<'a>,
) -> Option<ConstantValue> {
    let mut visited: HashSet<SymbolId> = HashSet::new();
    resolve_constant_inner(semantic, expression, &mut visited)
}

fn resolve_constant_inner<'a>(
    semantic: &Semantic<'a>,
    expression: &'a Expression<'a>,
    visited: &mut HashSet<SymbolId>,
) -> Option<ConstantValue> {
    let expression = unparenthesized(expression);
    if let Expression::Identifier(identifier) = expression {
        if identifier.name != "undefined" {
            if let Some(init) = resolve_const_binding(semantic, identifier, visited) {
                return resolve_constant_inner(semantic, init, visited);
            }
        }
    }
    match expression {
        Expression::NullLiteral(_) => Some(ConstantValue::Null),
        Expression::BooleanLiteral(literal) => Some(ConstantValue::Boolean(literal.value)),
        Expression::NumericLiteral(literal) => Some(ConstantValue::Number(literal.value)),
        Expression::StringLiteral(literal) => {
            Some(ConstantValue::String(literal.value.to_string()))
        }
        Expression::BigIntLiteral(literal) => {
            parse_bigint(&literal.value).map(ConstantValue::BigInt)
        }
        Expression::Identifier(identifier) => (identifier.name == "undefined"
            && reference_symbol(semantic, identifier).is_none())
        .then_some(ConstantValue::Undefined),
        Expression::TemplateLiteral(template) => {
            if !template.expressions.is_empty() {
                return None;
            }
            template
                .quasis
                .first()
                .and_then(|quasi| quasi.value.cooked.as_ref())
                .map(|cooked| ConstantValue::String(cooked.to_string()))
        }
        Expression::UnaryExpression(unary) => resolve_unary(semantic, unary, visited),
        Expression::BinaryExpression(binary) => resolve_binary(
            semantic,
            &binary.left,
            binary.operator.into(),
            &binary.right,
            visited,
        ),
        Expression::LogicalExpression(logical) => resolve_binary(
            semantic,
            &logical.left,
            logical.operator.into(),
            &logical.right,
            visited,
        ),
        _ => None,
    }
}

fn parse_bigint(value: &str) -> Option<i128> {
    value.parse::<i128>().ok()
}

/// Unary operators preserving constness: `!`, `+`, `-`, `typeof`, `void`.
fn resolve_unary<'a>(
    semantic: &Semantic<'a>,
    unary: &'a oxc_ast::ast::UnaryExpression<'a>,
    visited: &mut HashSet<SymbolId>,
) -> Option<ConstantValue> {
    use oxc_ast::ast::UnaryOperator;
    if unary.operator == UnaryOperator::Void {
        return Some(ConstantValue::Undefined);
    }
    let argument = resolve_constant_inner(semantic, &unary.argument, visited)?;
    match unary.operator {
        UnaryOperator::LogicalNot => Some(ConstantValue::Boolean(!argument.truthy())),
        UnaryOperator::UnaryPlus => to_number(&argument).map(ConstantValue::Number),
        UnaryOperator::UnaryNegation => match argument {
            ConstantValue::BigInt(value) => Some(ConstantValue::BigInt(-value)),
            other => to_number(&other).map(|value| ConstantValue::Number(-value)),
        },
        UnaryOperator::Typeof => Some(ConstantValue::String(
            match argument {
                ConstantValue::Null => "object",
                ConstantValue::Undefined => "undefined",
                ConstantValue::Boolean(_) => "boolean",
                ConstantValue::Number(_) => "number",
                ConstantValue::String(_) => "string",
                ConstantValue::BigInt(_) => "bigint",
            }
            .to_string(),
        )),
        _ => None,
    }
}

/// `ToNumber` for the constant primitives (string parsing covers the
/// JS numeric literal forms: decimal, exponent, hex/octal/binary, Infinity).
fn to_number(value: &ConstantValue) -> Option<f64> {
    match value {
        ConstantValue::Null => Some(0.0),
        ConstantValue::Undefined => Some(f64::NAN),
        ConstantValue::Boolean(value) => Some(if *value { 1.0 } else { 0.0 }),
        ConstantValue::Number(value) => Some(*value),
        ConstantValue::String(value) => Some(string_to_number(value)),
        ConstantValue::BigInt(_) => None,
    }
}

fn string_to_number(value: &str) -> f64 {
    let trimmed = value.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if trimmed.is_empty() {
        return 0.0;
    }
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let magnitude = if digits.eq_ignore_ascii_case("infinity") {
        f64::INFINITY
    } else if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map(|v| v as f64)
            .unwrap_or(f64::NAN)
    } else if let Some(octal) = digits
        .strip_prefix("0o")
        .or_else(|| digits.strip_prefix("0O"))
    {
        u64::from_str_radix(octal, 8)
            .map(|v| v as f64)
            .unwrap_or(f64::NAN)
    } else if let Some(binary) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        u64::from_str_radix(binary, 2)
            .map(|v| v as f64)
            .unwrap_or(f64::NAN)
    } else {
        digits.parse::<f64>().unwrap_or(f64::NAN)
    };
    if negative { -magnitude } else { magnitude }
}

/// `ToBigInt` for strings (integer literal syntax only).
fn string_to_bigint(value: &str) -> Option<i128> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Some(0);
    }
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let parsed = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i128::from_str_radix(hex, 16).ok()
    } else if let Some(octal) = digits
        .strip_prefix("0o")
        .or_else(|| digits.strip_prefix("0O"))
    {
        i128::from_str_radix(octal, 8).ok()
    } else if let Some(binary) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        i128::from_str_radix(binary, 2).ok()
    } else if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        digits.parse::<i128>().ok()
    } else {
        None
    };
    parsed.map(|value| if negative { -value } else { value })
}

/// Unified binary/logical operator tag mirroring the reference evaluator.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Exp,
    StrictEq,
    StrictNe,
    LooseEq,
    LooseNe,
    Lt,
    Le,
    Gt,
    Ge,
    Shl,
    Shr,
    Ushr,
    BitAnd,
    BitOr,
    BitXor,
    And,
    Or,
    Nullish,
    Unsupported,
}

impl From<oxc_ast::ast::BinaryOperator> for BinaryOp {
    fn from(operator: oxc_ast::ast::BinaryOperator) -> Self {
        use oxc_ast::ast::BinaryOperator as Op;
        match operator {
            Op::Addition => Self::Add,
            Op::Subtraction => Self::Sub,
            Op::Multiplication => Self::Mul,
            Op::Division => Self::Div,
            Op::Remainder => Self::Rem,
            Op::Exponential => Self::Exp,
            Op::StrictEquality => Self::StrictEq,
            Op::StrictInequality => Self::StrictNe,
            Op::Equality => Self::LooseEq,
            Op::Inequality => Self::LooseNe,
            Op::LessThan => Self::Lt,
            Op::LessEqualThan => Self::Le,
            Op::GreaterThan => Self::Gt,
            Op::GreaterEqualThan => Self::Ge,
            Op::ShiftLeft => Self::Shl,
            Op::ShiftRight => Self::Shr,
            Op::ShiftRightZeroFill => Self::Ushr,
            Op::BitwiseAnd => Self::BitAnd,
            Op::BitwiseOR => Self::BitOr,
            Op::BitwiseXOR => Self::BitXor,
            _ => Self::Unsupported,
        }
    }
}

impl From<LogicalOperator> for BinaryOp {
    fn from(operator: LogicalOperator) -> Self {
        match operator {
            LogicalOperator::And => Self::And,
            LogicalOperator::Or => Self::Or,
            LogicalOperator::Coalesce => Self::Nullish,
        }
    }
}

fn resolve_binary<'a>(
    semantic: &Semantic<'a>,
    left: &'a Expression<'a>,
    operator: BinaryOp,
    right: &'a Expression<'a>,
    visited: &mut HashSet<SymbolId>,
) -> Option<ConstantValue> {
    if operator == BinaryOp::Unsupported {
        return None;
    }
    let mut left_visited = visited.clone();
    let left_value = resolve_constant_inner(semantic, left, &mut left_visited)?;
    // Short-circuiting operators skip the right operand when it is never
    // evaluated.
    match operator {
        BinaryOp::And if !left_value.truthy() => return Some(left_value),
        BinaryOp::Or if left_value.truthy() => return Some(left_value),
        BinaryOp::Nullish
            if !matches!(left_value, ConstantValue::Null | ConstantValue::Undefined) =>
        {
            return Some(left_value);
        }
        _ => {}
    }
    let mut right_visited = visited.clone();
    let right_value = resolve_constant_inner(semantic, right, &mut right_visited)?;
    visited.extend(left_visited.iter().chain(right_visited.iter()));
    evaluate_binary(operator, &left_value, &right_value)
}

fn evaluate_binary(
    operator: BinaryOp,
    left: &ConstantValue,
    right: &ConstantValue,
) -> Option<ConstantValue> {
    match operator {
        BinaryOp::And | BinaryOp::Or => Some(right.clone()),
        BinaryOp::Nullish => Some(right.clone()),
        BinaryOp::StrictEq => Some(ConstantValue::Boolean(strict_equals(left, right))),
        BinaryOp::StrictNe => Some(ConstantValue::Boolean(!strict_equals(left, right))),
        BinaryOp::LooseEq => Some(ConstantValue::Boolean(loose_equals(left, right))),
        BinaryOp::LooseNe => Some(ConstantValue::Boolean(!loose_equals(left, right))),
        BinaryOp::Add => eval_add(left, right),
        BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem | BinaryOp::Exp => {
            eval_numeric(operator, left, right)
        }
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            eval_relational(operator, left, right)
        }
        BinaryOp::Shl
        | BinaryOp::Shr
        | BinaryOp::Ushr
        | BinaryOp::BitAnd
        | BinaryOp::BitOr
        | BinaryOp::BitXor => eval_bitwise(operator, left, right),
        BinaryOp::Unsupported => None,
    }
}

/// `+` concatenates when either side is a string; otherwise numeric.
fn eval_add(left: &ConstantValue, right: &ConstantValue) -> Option<ConstantValue> {
    if matches!(left, ConstantValue::String(_)) || matches!(right, ConstantValue::String(_)) {
        return Some(ConstantValue::String(format!(
            "{}{}",
            primitive_to_string(left),
            primitive_to_string(right)
        )));
    }
    eval_numeric(BinaryOp::Add, left, right)
}

fn primitive_to_string(value: &ConstantValue) -> String {
    match value {
        ConstantValue::Null => "null".to_string(),
        ConstantValue::Undefined => "undefined".to_string(),
        ConstantValue::Boolean(value) => value.to_string(),
        ConstantValue::Number(value) => number_to_js_string(*value),
        ConstantValue::String(value) => value.clone(),
        ConstantValue::BigInt(value) => value.to_string(),
    }
}

fn number_to_js_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-Infinity" } else { "Infinity" }.to_string();
    }
    if value == 0.0 {
        return "0".to_string();
    }
    if value.fract() == 0.0 && value.abs() < 1e21 {
        return format!("{value:.0}");
    }
    format!("{value}")
}

/// Numeric arithmetic; mixed number/bigint operands are a TypeError
/// (unresolvable), bigint arithmetic uses i128.
fn eval_numeric(
    operator: BinaryOp,
    left: &ConstantValue,
    right: &ConstantValue,
) -> Option<ConstantValue> {
    if let (ConstantValue::BigInt(a), ConstantValue::BigInt(b)) = (left, right) {
        let value = match operator {
            BinaryOp::Add => a.checked_add(*b),
            BinaryOp::Sub => a.checked_sub(*b),
            BinaryOp::Mul => a.checked_mul(*b),
            BinaryOp::Div => (*b != 0).then(|| a / b),
            BinaryOp::Rem => (*b != 0).then(|| a % b),
            BinaryOp::Exp => u32::try_from(*b).ok().and_then(|e| a.checked_pow(e)),
            _ => None,
        }?;
        return Some(ConstantValue::BigInt(value));
    }
    if matches!(left, ConstantValue::BigInt(_)) || matches!(right, ConstantValue::BigInt(_)) {
        return None;
    }
    let a = to_number(left)?;
    let b = to_number(right)?;
    let value = match operator {
        BinaryOp::Add => a + b,
        BinaryOp::Sub => a - b,
        BinaryOp::Mul => a * b,
        BinaryOp::Div => a / b,
        BinaryOp::Rem => a % b,
        BinaryOp::Exp => a.powf(b),
        _ => return None,
    };
    Some(ConstantValue::Number(value))
}

fn eval_relational(
    operator: BinaryOp,
    left: &ConstantValue,
    right: &ConstantValue,
) -> Option<ConstantValue> {
    // String < string compares lexicographically; otherwise numeric.
    if let (ConstantValue::String(a), ConstantValue::String(b)) = (left, right) {
        let result = match operator {
            BinaryOp::Lt => a < b,
            BinaryOp::Le => a <= b,
            BinaryOp::Gt => a > b,
            BinaryOp::Ge => a >= b,
            _ => return None,
        };
        return Some(ConstantValue::Boolean(result));
    }
    if let (ConstantValue::BigInt(a), ConstantValue::BigInt(b)) = (left, right) {
        let result = match operator {
            BinaryOp::Lt => a < b,
            BinaryOp::Le => a <= b,
            BinaryOp::Gt => a > b,
            BinaryOp::Ge => a >= b,
            _ => return None,
        };
        return Some(ConstantValue::Boolean(result));
    }
    let a = to_number(left)?;
    let b = to_number(right)?;
    if a.is_nan() || b.is_nan() {
        return Some(ConstantValue::Boolean(false));
    }
    let result = match operator {
        BinaryOp::Lt => a < b,
        BinaryOp::Le => a <= b,
        BinaryOp::Gt => a > b,
        BinaryOp::Ge => a >= b,
        _ => return None,
    };
    Some(ConstantValue::Boolean(result))
}

/// Bitwise/shift operators coerce through `ToInt32`/`ToUint32`.
fn eval_bitwise(
    operator: BinaryOp,
    left: &ConstantValue,
    right: &ConstantValue,
) -> Option<ConstantValue> {
    if matches!(left, ConstantValue::BigInt(_)) || matches!(right, ConstantValue::BigInt(_)) {
        return None;
    }
    let a = to_number(left)?;
    let b = to_number(right)?;
    let a_i32 = a as i32;
    let b_u32 = (b as i64) as u32 & 0x1f;
    let value = match operator {
        BinaryOp::Shl => a_i32.wrapping_shl(b_u32) as f64,
        BinaryOp::Shr => a_i32.wrapping_shr(b_u32) as f64,
        BinaryOp::Ushr => ((a_i32 as u32).wrapping_shr(b_u32)) as f64,
        BinaryOp::BitAnd => (a_i32 & (b as i32)) as f64,
        BinaryOp::BitOr => (a_i32 | (b as i32)) as f64,
        BinaryOp::BitXor => (a_i32 ^ (b as i32)) as f64,
        _ => return None,
    };
    Some(ConstantValue::Number(value))
}

/// Abstract equality (`==`) over constant primitives.
pub(crate) fn loose_equals(left: &ConstantValue, right: &ConstantValue) -> bool {
    use ConstantValue as C;
    match (left, right) {
        (C::Null, C::Null)
        | (C::Null, C::Undefined)
        | (C::Undefined, C::Null)
        | (C::Undefined, C::Undefined) => true,
        (C::Number(a), C::Number(b)) => a == b,
        (C::String(a), C::String(b)) => a == b,
        (C::Boolean(a), C::Boolean(b)) => a == b,
        (C::BigInt(a), C::BigInt(b)) => a == b,
        (C::Number(_), C::String(b)) => to_number(left) == Some(string_to_number(b)),
        (C::String(a), C::Number(b)) => string_to_number(a) == *b,
        (C::Boolean(_), _) => {
            to_number(left).is_some_and(|a| loose_equals(&ConstantValue::Number(a), right))
        }
        (_, C::Boolean(_)) => {
            to_number(right).is_some_and(|b| loose_equals(left, &ConstantValue::Number(b)))
        }
        (C::BigInt(a), C::Number(b)) | (C::Number(b), C::BigInt(a)) => {
            b.fract() == 0.0 && b.is_finite() && *a == *b as i128
        }
        (C::BigInt(a), C::String(b)) | (C::String(b), C::BigInt(a)) => {
            string_to_bigint(b) == Some(*a)
        }
        _ => false,
    }
}

/// `resolveConstBinding`: the initializer of a `const` binding declared
/// with a plain identifier pattern, honoring the visited set and the
/// same-execution-context TDZ check.
fn resolve_const_binding<'a>(
    semantic: &Semantic<'a>,
    identifier: &'a IdentifierReference<'a>,
    visited: &mut HashSet<SymbolId>,
) -> Option<&'a Expression<'a>> {
    let reference = semantic
        .scoping()
        .get_reference(identifier.reference_id.get()?);
    let symbol = reference.symbol_id()?;
    if visited.contains(&symbol) || semantic.scoping().symbol_declarations(symbol).count() != 1 {
        return None;
    }
    let declaration = semantic.symbol_declaration(symbol);
    let AstKind::VariableDeclarator(declarator) = semantic.nodes().kind(declaration.id()) else {
        return None;
    };
    let AstKind::VariableDeclaration(declaration_kind) =
        semantic.nodes().parent_kind(declaration.id())
    else {
        return None;
    };
    if declaration_kind.kind != VariableDeclarationKind::Const {
        return None;
    }
    let BindingPattern::BindingIdentifier(_) = declarator.id else {
        return None;
    };
    let init = declarator.init.as_ref()?;
    // TDZ: a read before its `const` in the same execution context is a
    // guaranteed crash, so the binding is not a usable constant there.
    let read_context = execution_context_scope(semantic, reference.scope_id());
    let declaration_scope = semantic.scoping().symbol_scope_id(symbol);
    let declaration_context = execution_context_scope(semantic, declaration_scope);
    if read_context == declaration_context && identifier.span.start < declarator.span.start {
        return None;
    }
    visited.insert(symbol);
    Some(init)
}

/// Nearest enclosing scope that is a distinct execution context
/// (function, arrow, top/module, or class static block), like the
/// reference `getExecutionContextScope`.
fn execution_context_scope(
    semantic: &Semantic<'_>,
    scope_id: oxc_syntax::scope::ScopeId,
) -> oxc_syntax::scope::ScopeId {
    const CONTEXT: ScopeFlags = ScopeFlags::Function
        .union(ScopeFlags::Arrow)
        .union(ScopeFlags::Top)
        .union(ScopeFlags::ClassStaticBlock);
    let mut current = scope_id;
    loop {
        let flags = semantic.scoping().scope_flags(current);
        if flags.intersects(CONTEXT) {
            return current;
        }
        match semantic.scoping().scope_parent_id(current) {
            Some(parent) => current = parent,
            None => return current,
        }
    }
}
