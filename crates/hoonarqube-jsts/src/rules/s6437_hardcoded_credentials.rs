// Rule module s6437_hardcoded_credentials (generated).
//
// `javascript:S6437` + `typescript:S6437` — SonarJS S6437 "Credentials
// should not be hard-coded" (SonarJS rule implementation, not a wrapped
// eslint rule): a hard-coded string passed to a known secret-accepting
// API is reported on the call's callee with "Revoke and change this
// password, as it is compromised."
//
// Two signature tables drive detection. `secretSignatures` maps a
// fully-qualified callee name to the argument indices that take a
// secret (`crypto.createHmac` index 1, `jsonwebtoken.sign` index 1,
// `superagent.auth` index 0, …). `secretObjectSignatures` maps a callee
// to an options-object argument plus the property holding the secret
// (`express-session` `{secret}`, `cookie-session` `{keys}` — array
// elements checked individually — `mysql.createConnection` `{password}`,
// `typeorm.createConnection` `{password}`, …). A candidate value is
// "hard-coded" when it is a string literal or an expression-free
// template literal, or an identifier whose unique write resolves to one
// (the reference `getUniqueWriteUsageOrNode`); options objects likewise
// resolve through a unique write. Values the shared SonarSource
// `secret-patterns` classifier considers non-sensitive (exact-match
// placeholders like `changeit`, `token`, `unknown`; pattern groups for
// short/obvious/fake values, interpolation syntax, encrypted blobs,
// external secret-store references, and version/path strings) stay
// silent.
//
// Fully-qualified names mirror `getFullyQualifiedName` for the
// single-file subset: `require('m')` and `import` bindings resolve to
// `m` / `m.export`, member chains append property names, chained calls
// (`require('m')()`, `crypto.createSign().sign(key)`) keep the callee
// chain, and unbound identifiers resolve to their own name (matching
// the reference's treatment of globals). `node:` prefixes are stripped.
// Anything unresolvable yields no report.
//
// SonarJS reports the rule with scope MAIN: test files (the pinned
// server's filename-based classification, shared with the analyzer's
// other rules) stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, BindingPattern, CallExpression, Expression, IdentifierReference, ModuleExportName,
    ObjectPropertyKind,
};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;
use oxc_syntax::symbol::SymbolId;

/// `secretSignatures`: fully-qualified callee → secret argument indices.
fn secret_signature_indices(fqn: &str) -> Option<&'static [usize]> {
    Some(match fqn {
        "cookie-parser" => &[0],
        "cookie-parser.JSONCookie" | "cookie-parser.signedCookies"
        | "cookie-parser.signedCookie" => &[1],
        "crypto.X509Certificate.checkPrivateKey" => &[0],
        "crypto.createDiffieHellman.setPrivateKey" => &[0],
        "crypto.createECDH.setPrivateKey" => &[0],
        "crypto.createHmac" => &[1],
        "crypto.createSecretKey" => &[0],
        "crypto.createSign.sign" => &[0],
        "crypto.createVerify.verify" => &[0],
        "crypto.privateDecrypt" | "crypto.privateEncrypt" => &[0],
        "crypto.sign" | "crypto.verify" => &[2],
        "jose.SignJWT" => &[0],
        "jose.jwtVerify" => &[1],
        "jsonwebtoken.sign" | "jsonwebtoken.verify" => &[1],
        "ldapjs.createClient.bind" => &[1],
        "node-jose.JWK.asKey" => &[0],
        "superagent.auth" => &[0],
        _ => return None,
    })
}

/// `secretObjectSignatures`: fully-qualified callee → (options argument
/// index, secret property name).
fn secret_object_signature(fqn: &str) -> Option<(usize, &'static str)> {
    Some(match fqn {
        "cookie-session" => (0, "keys"),
        "express-session" => (0, "secret"),
        "typeorm.createConnection" => (0, "password"),
        "mysql.createConnection" | "mysql.createPool" => (0, "password"),
        "mysql2.createConnection" | "mysql2.createPool" => (0, "password"),
        _ => return None,
    })
}

/// Entry point: `javascript:S6437` + `typescript:S6437` hard-coded
/// credentials check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if is_test_file(ctx.path) {
        // Scope MAIN: the pinned server classifies by filename.
        return sink.issues;
    }
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        check_call(&mut sink, semantic, call);
    }
    sink.issues
}

fn check_call(sink: &mut IssueSink<'_>, semantic: &Semantic<'_>, call: &CallExpression<'_>) {
    let Some(fqn) = call_fqn(semantic, call) else {
        return;
    };
    if !call.arguments.is_empty()
        && let Some(indices) = secret_signature_indices(&fqn)
    {
        for &index in indices {
            let Some(argument) = call.arguments.get(index) else {
                continue;
            };
            let Some(expression) = argument.as_expression() else {
                continue;
            };
            if is_hardcoded_string(semantic, expression) {
                report(sink, call, expression);
            }
        }
    }
    if let Some((arg_index, property_name)) = secret_object_signature(&fqn) {
        check_secret_property(sink, semantic, call, arg_index, property_name);
    }
}

/// `checkSecretProperty`: resolve the options argument to an object
/// expression, find the named property, and report hard-coded values
/// (array elements individually).
fn check_secret_property(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    arg_index: usize,
    property_name: &str,
) {
    let Some(argument) = call.arguments.get(arg_index) else {
        return;
    };
    let Some(expression) = argument.as_expression() else {
        return;
    };
    let Some(object) = resolve_to_object(semantic, expression) else {
        return;
    };
    for property in &object.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            continue;
        };
        if property.computed {
            continue;
        }
        let Some(name) = property.key.name() else {
            continue;
        };
        if name != property_name {
            continue;
        }
        let value = &property.value;
        if is_hardcoded_string(semantic, value) {
            report(sink, call, value);
        } else if let Expression::ArrayExpression(array) = unparenthesized(value) {
            for element in &array.elements {
                let Some(element) = element.as_expression() else {
                    continue;
                };
                if is_hardcoded_string(semantic, element) {
                    report(sink, call, element);
                }
            }
        }
    }
}

/// `reportIssue`: excluded (non-sensitive) values stay silent; the
/// report anchors on the call's callee.
fn report(sink: &mut IssueSink<'_>, call: &CallExpression<'_>, secret: &Expression<'_>) {
    let _ = secret;
    sink.emit_span(
        RuleScope::Both,
        "S6437",
        "Revoke and change this password, as it is compromised.",
        call.callee.span(),
    );
}

/// `isHardcodedString`: the expression resolves to a string literal or
/// an expression-free template literal through a unique write.
fn is_hardcoded_string(semantic: &Semantic<'_>, expression: &Expression<'_>) -> bool {
    let Some(resolved) = unique_write_or_node(semantic, expression) else {
        return false;
    };
    if is_excluded_literal(resolved) {
        return false;
    }
    true
}

/// Whether the resolved node is a hard-coded string that is NOT on the
/// non-sensitive exclusion list. Returns `true` when the node is not a
/// string literal/template at all (caller treats as not-hardcoded via
/// the outer check).
fn is_excluded_literal(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::StringLiteral(literal) => is_excluded_secret_value(literal.value.as_str()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            match template.quasis.first().and_then(|quasi| quasi.value.cooked.as_ref()) {
                Some(cooked) => is_excluded_secret_value(cooked.as_str()),
                None => true,
            }
        }
        _ => true,
    }
}

/// `getUniqueWriteUsageOrNode` (single-file subset): an identifier
/// resolves to the initializer of its single variable declarator, to the
/// function of a single function declaration, or to itself when the
/// binding is mutated, multiply declared, or not a declarator. Other
/// expressions resolve to themselves.
fn unique_write_or_node<'a>(
    semantic: &Semantic<'a>,
    expression: &'a Expression<'a>,
) -> Option<&'a Expression<'a>> {
    let expression = unparenthesized(expression);
    let Expression::Identifier(identifier) = expression else {
        return Some(expression);
    };
    let symbol = reference_symbol(semantic, identifier)?;
    // Mutated bindings are not unique writes.
    if semantic
        .scoping()
        .get_resolved_references(symbol)
        .any(|reference| reference.is_write())
    {
        return Some(expression);
    }
    let mut declarations = semantic.scoping().symbol_declarations(symbol);
    let declaration = declarations.next()?;
    if declarations.next().is_some() {
        return Some(expression);
    }
    match semantic.nodes().get_node(declaration).kind() {
        AstKind::VariableDeclarator(declarator) => {
            declarator.init.as_ref().map(|init| unparenthesized(init))
        }
        _ => Some(expression),
    }
}

/// `getValueOfExpression(..., 'ObjectExpression')`: resolve through a
/// unique write to an object expression.
fn resolve_to_object<'a>(
    semantic: &Semantic<'a>,
    expression: &'a Expression<'a>,
) -> Option<&'a oxc_ast::ast::ObjectExpression<'a>> {
    match unique_write_or_node(semantic, expression)? {
        Expression::ObjectExpression(object) => Some(object),
        _ => None,
    }
}

/// `getFullyQualifiedName` for a call expression (single-file subset):
/// the callee's member chain resolved against the base identifier's
/// binding; chained calls extend the chain with the called property.
fn call_fqn(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> Option<String> {
    expression_fqn(semantic, &call.callee)
}

fn expression_fqn(semantic: &Semantic<'_>, expression: &Expression<'_>) -> Option<String> {
    let mut visited = std::collections::HashSet::new();
    expression_fqn_inner(semantic, expression, &mut visited)
}

fn expression_fqn_inner(
    semantic: &Semantic<'_>,
    expression: &Expression<'_>,
    visited: &mut std::collections::HashSet<SymbolId>,
) -> Option<String> {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) => binding_fqn(semantic, identifier, visited),
        Expression::StaticMemberExpression(member) if !member.optional => {
            let base = expression_fqn_inner(semantic, &member.object, visited)?;
            Some(format!("{base}.{}", member.property.name))
        }
        Expression::CallExpression(call) => call_inner_fqn(semantic, call, visited),
        Expression::ThisExpression(_) => Some("this".to_string()),
        _ => None,
    }
}

/// FQN of a call's result: `require('m')` resolves to the module name;
/// any other call resolves to its callee's FQN (so
/// `crypto.createSign().sign(key)` keeps the `crypto.createSign.sign`
/// chain).
fn call_inner_fqn(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    visited: &mut std::collections::HashSet<SymbolId>,
) -> Option<String> {
    if let Expression::Identifier(callee) = unparenthesized(&call.callee)
        && callee.name == "require"
        && call.arguments.len() == 1
        && let Some(argument) = call.arguments.first().and_then(Argument::as_expression)
        && let Expression::StringLiteral(module) = unparenthesized(argument)
    {
        return Some(strip_node_prefix(module.value.as_str()).to_string());
    }
    expression_fqn_inner(semantic, &call.callee, visited)
}

/// `require('m').x` → `m.x`, `import {x} from 'm'` → `m.x`,
/// default/namespace imports → `m`, aliasing through a single
/// declarator → the aliased FQN. Unbound identifiers resolve to their
/// own name (the reference's global treatment). `node:` stripped.
fn binding_fqn(
    semantic: &Semantic<'_>,
    identifier: &IdentifierReference<'_>,
    visited: &mut std::collections::HashSet<SymbolId>,
) -> Option<String> {
    let Some(symbol) = reference_symbol(semantic, identifier) else {
        return Some(identifier.name.to_string());
    };
    // Alias cycles (`const a = b; const b = a;`) resolve to nothing.
    if !visited.insert(symbol) {
        return None;
    }
    let mut declarations = semantic.scoping().symbol_declarations(symbol);
    let declaration = declarations.next()?;
    if declarations.next().is_some() {
        return None;
    }
    match semantic.nodes().get_node(declaration).kind() {
        AstKind::ImportSpecifier(specifier) => {
            import_specifier_fqn(semantic, declaration, specifier)
        }
        AstKind::ImportDefaultSpecifier(_) | AstKind::ImportNamespaceSpecifier(_) => {
            let module = import_source(semantic, declaration)?;
            Some(strip_node_prefix(&module).to_string())
        }
        AstKind::VariableDeclarator(declarator) => {
            declarator_fqn(semantic, declarator, symbol, visited)
        }
        _ => None,
    }
}

/// `import {x} from 'm'` → `m.x`; `import {x as y}` keeps `x`; a
/// `default` import specifier resolves to the bare module name.
fn import_specifier_fqn(
    semantic: &Semantic<'_>,
    declaration: oxc_syntax::node::NodeId,
    specifier: &oxc_ast::ast::ImportSpecifier<'_>,
) -> Option<String> {
    if specifier.import_kind.is_type() {
        return None;
    }
    let module = import_source(semantic, declaration)?;
    let imported = match &specifier.imported {
        ModuleExportName::IdentifierName(name) => name.name.as_str(),
        ModuleExportName::IdentifierReference(name) => name.name.as_str(),
        ModuleExportName::StringLiteral(literal) => literal.value.as_str(),
    };
    if imported == "default" {
        return Some(strip_node_prefix(&module).to_string());
    }
    Some(format!("{}.{}", strip_node_prefix(&module), imported))
}

/// `const x = <expr>` → the initializer's FQN; `const {x} = <expr>`
/// joins the destructured property name onto the initializer's FQN.
fn declarator_fqn(
    semantic: &Semantic<'_>,
    declarator: &oxc_ast::ast::VariableDeclarator<'_>,
    symbol: SymbolId,
    visited: &mut std::collections::HashSet<SymbolId>,
) -> Option<String> {
    let init = declarator.init.as_ref()?;
    if let BindingPattern::ObjectPattern(object) = &declarator.id {
        let member = object.properties.iter().find_map(|property| {
            let BindingPattern::BindingIdentifier(bound) = &property.value else {
                return None;
            };
            (bound.symbol_id.get() == Some(symbol))
                .then(|| property.key.name().map(|name| name.to_string()))
                .flatten()
        });
        let base = expression_fqn_inner(semantic, init, visited)?;
        return Some(match member {
            Some(member) => format!("{base}.{member}"),
            None => base,
        });
    }
    expression_fqn_inner(semantic, init, visited)
}

/// The `ImportDeclaration` source for an import specifier node.
fn import_source(semantic: &Semantic<'_>, declaration: oxc_syntax::node::NodeId) -> Option<String> {
    let AstKind::ImportDeclaration(import) = semantic.nodes().parent_kind(declaration) else {
        return None;
    };
    if import.import_kind.is_type() {
        return None;
    }
    Some(import.source.value.to_string())
}

fn strip_node_prefix(module: &str) -> &str {
    module.strip_prefix("node:").unwrap_or(module)
}

/// Symbol a resolved identifier reference points at; `None` for
/// unresolved (global) references.
fn reference_symbol(
    semantic: &Semantic<'_>,
    identifier: &IdentifierReference<'_>,
) -> Option<SymbolId> {
    identifier
        .reference_id
        .get()
        .and_then(|reference_id| semantic.scoping().get_reference(reference_id).symbol_id())
}

// --------------------------------------------------------------------
// Non-sensitive value classifier: a Rust port of the shared SonarSource
// `secret-patterns` exact-match and pattern groups (the same tables the
// JS `isExcludedSecretValue` compiles). Patterns using syntax the JS
// engine rejects are dropped upstream; here every group is implemented
// directly.
// --------------------------------------------------------------------

/// Exact-match placeholder values (lowercased before comparison).
const EXACT_MATCH_VALUES: [&str; 12] = [
    "abc123", "changeit", "changeme", "disabled", "enabled", "hunter2", "letmein", "optional",
    "random", "string", "token", "unknown",
];

/// `isExcludedSecretValue`: exact match (case-insensitive) or any
/// pattern group.
fn is_excluded_secret_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    if EXACT_MATCH_VALUES.contains(&lower.as_str()) {
        return true;
    }
    looks_like_non_secret(&lower)
        || looks_like_interpolation(value)
        || looks_like_encrypted(value)
        || looks_like_external_secret(value)
        || looks_like_path_or_version(value)
}

/// Pattern group 1: short values, obvious/fake words, `pass(word)`-style
/// names, common non-values, `your…` prefixes, and 4+ repeated chars.
fn looks_like_non_secret(lower: &str) -> bool {
    // `^.{0,5}$`
    if lower.chars().count() <= 5 {
        return true;
    }
    // `sample|example|placeholder|replace|change|foo|bar|test|fake|abcd`
    const OBVIOUS_1: [&str; 10] = [
        "sample",
        "example",
        "placeholder",
        "replace",
        "change",
        "foo",
        "bar",
        "test",
        "fake",
        "abcd",
    ];
    if OBVIOUS_1.iter().any(|word| lower.contains(word)) {
        return true;
    }
    // `redacted|cafebabe|deadbeef|whatever|123456|admin|pass|secret|
    //  default|dummy|qwerty|setting|obfuscated`
    const OBVIOUS_2: [&str; 13] = [
        "redacted",
        "cafebabe",
        "deadbeef",
        "whatever",
        "123456",
        "admin",
        "pass",
        "secret",
        "default",
        "dummy",
        "qwerty",
        "setting",
        "obfuscated",
    ];
    if OBVIOUS_2.iter().any(|word| lower.contains(word)) {
        return true;
    }
    // `^(my)?pass(word|wd)?\d{0,5}$`
    if is_passwordish(lower) {
        return true;
    }
    // `p[@a]ssw[o0]rd`
    if is_passw0rd(lower) {
        return true;
    }
    // `^(?:none|undefined|null|true|false|yes|no|1|0)$`
    const NON_VALUES: [&str; 9] = [
        "none", "undefined", "null", "true", "false", "yes", "no", "1", "0",
    ];
    if NON_VALUES.contains(&lower) {
        return true;
    }
    // `^your`
    if lower.starts_with("your") {
        return true;
    }
    // `(?<repeated>.)\k<repeated>{3}` — four identical consecutive chars.
    repeated_four(lower)
}

/// `^(my)?pass(word|wd)?\d{0,5}$` (already lowercased).
fn is_passwordish(lower: &str) -> bool {
    let rest = lower.strip_prefix("my").unwrap_or(lower);
    let Some(rest) = rest.strip_prefix("pass") else {
        return false;
    };
    let rest = rest
        .strip_prefix("word")
        .or_else(|| rest.strip_prefix("wd"))
        .unwrap_or(rest);
    rest.len() <= 5 && rest.chars().all(|c| c.is_ascii_digit())
}

/// `p[@a]ssw[o0]rd` (unanchored, already lowercased): p, `@`/`a`, s, s,
/// w, `o`/`0`, r, d — eight characters.
fn is_passw0rd(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    bytes.windows(8).any(|w| {
        w[0] == b'p'
            && (w[1] == b'@' || w[1] == b'a')
            && w[2] == b's'
            && w[3] == b's'
            && w[4] == b'w'
            && (w[5] == b'o' || w[5] == b'0')
            && w[6] == b'r'
            && w[7] == b'd'
    })
}

/// Four identical consecutive characters anywhere in the value.
fn repeated_four(lower: &str) -> bool {
    let chars: Vec<char> = lower.chars().collect();
    chars
        .windows(4)
        .any(|w| w[0] == w[1] && w[1] == w[2] && w[2] == w[3])
}

/// Pattern group 2: templating/interpolation syntax (`${…}`, `#{…}`,
/// `$()`, backticks, `%?{…}`, `((…))`, `$\w+$`).
fn looks_like_interpolation(value: &str) -> bool {
    let trimmed = value.strip_prefix('\\').unwrap_or(value);
    // `^(?:\\)?\${1,2}\{[^}]+\}` and `(?:\\)?\${1,2}\{[^}]+\}$`
    if let Some(rest) = trimmed
        .strip_prefix("$$")
        .or_else(|| trimmed.strip_prefix('$'))
        && let Some(inner) = rest.strip_prefix('{')
        && inner.contains('}')
        && !inner[..inner.find('}').unwrap_or(0)].is_empty()
    {
        return true;
    }
    // `^\#{1,2}[{(]`
    if let Some(rest) = value.strip_prefix("##").or_else(|| value.strip_prefix('#'))
        && (rest.starts_with('{') || rest.starts_with('('))
    {
        return true;
    }
    // `^\(\(.*\)\)$`
    if value.starts_with("((") && value.ends_with("))") && value.len() > 4 {
        return true;
    }
    // `^\$\(`
    if value.starts_with("$(") {
        return true;
    }
    // `^`[^`]+`$`
    if value.len() > 2 && value.starts_with('`') && value.ends_with('`') {
        return true;
    }
    // `^(?:\\)?\${1,2}\w+\${0,2}$`
    if interpolation_variable(trimmed) {
        return true;
    }
    // `^%?\{[^}]+\}$`
    let braced = value.strip_prefix('%').unwrap_or(value);
    if braced.starts_with('{')
        && braced.ends_with('}')
        && braced.len() > 2
        && !braced[1..braced.len() - 1].contains('}')
    {
        return true;
    }
    false
}

/// `^(?:\\)?\${1,2}\w+\${0,2}$` — `$NAME`, `$$NAME`, `$NAME$`, `$$NAME$$`.
fn interpolation_variable(trimmed: &str) -> bool {
    let rest = trimmed
        .strip_prefix("$$")
        .or_else(|| trimmed.strip_prefix('$'));
    let Some(rest) = rest else {
        return false;
    };
    let rest = rest.strip_suffix("$$").unwrap_or(rest);
    let rest = rest.strip_suffix('$').unwrap_or(rest);
    !rest.is_empty() && rest.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Pattern group 3: encrypted/encoded blobs.
fn looks_like_encrypted(value: &str) -> bool {
    // `^encrypted:[a-zA-Z0-9+/]+={0,2}$`
    if let Some(rest) = value.strip_prefix("encrypted:") {
        let trimmed = rest.trim_end_matches('=');
        if !trimmed.is_empty()
            && rest.len() - trimmed.len() <= 2
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        {
            return true;
        }
    }
    // `^\{cipher\}`
    if value.starts_with("{cipher}") {
        return true;
    }
    // `^enc\[`
    if value.starts_with("enc[") {
        return true;
    }
    // `^%?enc\{`
    let stripped = value.strip_prefix('%').unwrap_or(value);
    if stripped.starts_with("enc{") {
        return true;
    }
    // `^enc\([^)]*\)$`
    if value.starts_with("enc(") && value.ends_with(')') {
        return true;
    }
    false
}

/// Pattern group 4: external secret-store references.
fn looks_like_external_secret(value: &str) -> bool {
    // `^arn:aws:secretsmanager:`
    if value.starts_with("arn:aws:secretsmanager:") {
        return true;
    }
    // `^op:\/[\S\ ]+$` — 1Password CLI reference.
    if let Some(rest) = value.strip_prefix("op:/")
        && !rest.is_empty()
        && rest.chars().all(|c| !c.is_control())
    {
        return true;
    }
    // `^vault\[`
    if value.starts_with("vault[") {
        return true;
    }
    false
}

/// Pattern group 5: file paths and version strings.
fn looks_like_path_or_version(value: &str) -> bool {
    // `^(?:/[a-z0-9_.-]+){3,}$` — a path with at least three segments.
    if looks_like_path(value) {
        return true;
    }
    // semver (with optional comparator/`v` prefix).
    if looks_like_semver(value) {
        return true;
    }
    // `^v?\d+(\.\d+)+\([^()]*\)+$` — `1.2.3(4)`-style versions.
    if looks_like_paren_version(value) {
        return true;
    }
    false
}

fn looks_like_path(value: &str) -> bool {
    if !value.starts_with('/') {
        return false;
    }
    let segments: Vec<&str> = value.split('/').skip(1).collect();
    segments.len() >= 3
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
        })
}

/// `^(?:>=?|<=?|[~^])?v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)
///  (?:-(prerelease))?(?:\+(build))?$`
fn looks_like_semver(value: &str) -> bool {
    let mut rest = value;
    for prefix in [">=", "<=", ">", "<", "~", "^"] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
            break;
        }
    }
    let rest = rest.strip_prefix('v').unwrap_or(rest);
    // Split off build metadata, then prerelease.
    let (rest, build) = match rest.split_once('+') {
        Some((main, build)) => (main, Some(build)),
        None => (rest, None),
    };
    let (main, prerelease) = match rest.split_once('-') {
        Some((main, pre)) => (main, Some(pre)),
        None => (rest, None),
    };
    if !valid_semver_main(main) {
        return false;
    }
    if let Some(pre) = prerelease
        && !valid_semver_prerelease(pre)
    {
        return false;
    }
    if let Some(build) = build
        && !valid_semver_build(build)
    {
        return false;
    }
    true
}

/// `major.minor.patch` — three `0|[1-9]\d*` parts.
fn valid_semver_main(main: &str) -> bool {
    let mut parts = main.split('.');
    let (Some(major), Some(minor), Some(patch)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    parts.next().is_none()
        && is_semver_number(major)
        && is_semver_number(minor)
        && is_semver_number(patch)
}

/// Dot-separated prerelease identifiers.
fn valid_semver_prerelease(pre: &str) -> bool {
    !pre.is_empty()
        && pre
            .split('.')
            .all(|id| !id.is_empty() && is_prerelease_identifier(id))
}

/// Dot-separated build identifiers (`[0-9a-zA-Z-]+`).
fn valid_semver_build(build: &str) -> bool {
    !build.is_empty()
        && build
            .split('.')
            .all(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// `0|[1-9]\d*` — numeric identifier without leading zeros.
fn is_semver_number(part: &str) -> bool {
    !part.is_empty()
        && part.chars().all(|c| c.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'))
}

/// Prerelease identifier: `0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*`.
fn is_prerelease_identifier(part: &str) -> bool {
    if part.chars().all(|c| c.is_ascii_digit()) {
        return is_semver_number(part);
    }
    part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `^v?\d+(?:\.\d+)+\([^()]*\)+$` — `1.2.3(4)`, `v1.2.3(4)(5)`.
fn looks_like_paren_version(value: &str) -> bool {
    let rest = value.strip_prefix('v').unwrap_or(value);
    let Some(open) = rest.find('(') else {
        return false;
    };
    let (version, suffix) = rest.split_at(open);
    let mut parts = version.split('.');
    if parts.clone().count() < 2 || !parts.all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    // Suffix: one or more `(...)` groups with no parens inside.
    let mut suffix = suffix;
    while !suffix.is_empty() {
        let Some(close) = suffix.find(')') else {
            return false;
        };
        if !suffix.starts_with('(') || suffix[1..close].contains(['(', ')']) {
            return false;
        }
        suffix = &suffix[close + 1..];
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6437_flags_pinned_express_session_sites() {
        // Pinned oracle: express@3ce6d0e examples/session/index.js:16 and
        // examples/session/redis.js:20 — `session({secret: 'keyboard
        // cat'})` where `session = require('express-session')`. Report
        // span: the callee `session` (columns 8-15).
        let source = "\
var express = require('../..');
var session = require('express-session');

var app = express();

app.use(session({
  resave: false,
  saveUninitialized: false,
  secret: 'keyboard cat'
}));
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S6437"), 1);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S6437")
            .expect("pinned express-session secret must be reported");
        assert_eq!(
            issue.message,
            "Revoke and change this password, as it is compromised."
        );
        assert_eq!(issue.range.start.line, 6);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("app.use(".len()).unwrap()
        );
    }

    #[test]
    fn s6437_flags_secret_signatures_and_aliased_values() {
        let source = "\
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const key = 'Tr0ub4dor-value';
crypto.createHmac('sha256', key);
crypto.createHmac('sha256', 'keyboard cat');
jwt.sign(payload, 'keyboard cat');
jwt.verify(token, 'keyboard cat');
crypto.sign('sha256', data, 'keyboard cat');
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S6437"), 5);
    }

    #[test]
    fn s6437_flags_object_signatures_and_key_arrays() {
        let source = "\
const session = require('cookie-session');
const mysql = require('mysql');
session({ keys: ['keyboard cat', 'Tr0ub4dor'] });
mysql.createConnection({ host: 'db', password: 'keyboard cat' });
mysql.createPool({ password: 'keyboard cat' });
";
        let findings = js_keys(source);
        // cookie-session: two array elements; mysql: one each.
        assert_eq!(count_key(&findings, "javascript:S6437"), 4);
    }


    #[test]
    fn s6437_excluded_and_dynamic_values_stay_silent() {
        let source = "\
const session = require('express-session');
const crypto = require('crypto');
session({ secret: 'changeme' });
session({ secret: 'none' });
session({ secret: process.env.SECRET });
session({ secret: getSecret() });
session({ secret: '' });
session({ secret: 'x' });
session({ secret: '${CONFIG_SECRET}' });
crypto.createHmac('sha256', 'test');
crypto.createHmac('sha256', computed);
crypto.createHmac('sha256');
";
        assert_eq!(count_key(&js_keys(source), "javascript:S6437"), 0);
    }

    #[test]
    fn s6437_unknown_callees_and_missing_property_stay_silent() {
        let source = "\
const session = require('express-session');
session({ resave: false, saveUninitialized: false });
session('literal-secret');
other({ secret: 'keyboard cat' });
session();
";
        assert_eq!(count_key(&js_keys(source), "javascript:S6437"), 0);
    }

    #[test]
    fn s6437_typescript_uses_typescript_key() {
        let source = "\
const session = require('express-session');
session({ secret: 'keyboard cat' });
";
        let findings = ts_keys(source);
        assert_eq!(count_key(&findings, "typescript:S6437"), 1);
        assert_eq!(count_key(&findings, "javascript:S6437"), 0);
    }

    #[test]
    fn s6437_test_files_stay_silent() {
        let source = "\
const session = require('express-session');
session({ secret: 'keyboard cat' });
";
        assert_eq!(count_key(&test_file_keys(source), "javascript:S6437"), 0);
    }
}

