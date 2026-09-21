// Residual rule machinery for 'batch5' (extracted from lib.rs).
use super::s1607_s6426_skipped_or_focused::TEST_FRAMEWORK_GLOBALS;
use crate::JstsLanguage;
use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::support::IssueSink;
use crate::support::LineIndex;
use crate::support::callee_name;
use crate::support::span_issue;
use crate::support::span_text;
use crate::support::unparenthesized;
use hoonarqube_ir::Issue;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::ComputedMemberExpression;
use oxc_ast::ast::ExportDefaultDeclarationKind;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ExpressionStatement;
use oxc_ast::ast::Statement;
use oxc_ast::ast::StaticMemberExpression;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_catch_clause;
use oxc_ast_visit::walk::{
    walk_call_expression, walk_class, walk_computed_member_expression, walk_expression_statement,
    walk_function, walk_function_body, walk_program, walk_static_member_expression,
    walk_ts_module_block,
};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;
use std::path::{Component, Path, PathBuf};

/// Fragments whose absence in a callback body means `S2699` flags it.
pub(crate) const ASSERTION_MARKERS: [&str; 4] = ["expect(", "assert.", "assert(", "should"];

/// Collector for the remaining single-file Tier-A checks.
pub(crate) struct MiscCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Number of enclosing function boundaries (`S2990`).
    pub(crate) function_depth: u32,
    /// Number of enclosing class bodies (`S2990`): `this` inside a class is
    /// receiver-bound (field initializers, computed keys, static blocks).
    pub(crate) class_depth: u32,
    /// Number of enclosing `namespace`/`module` blocks (`S2990`): those
    /// compile to function wrappers, so `this` inside is not the global `this`.
    pub(crate) ts_module_depth: u32,
    /// Whether the file is a `CommonJS` module (`S2990`): top-level `this` is
    /// `module.exports`, not the global object.
    pub(crate) commonjs_module: bool,
}

impl<'a> Visit<'a> for MiscCollector<'_> {
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        self.commonjs_module =
            self.commonjs_module || super::s3798_s3798_program::program_is_commonjs(it);
        self.check_s3798_program(it);
        walk_program(self, it);
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        self.check_s1539_expression_statement(it);
        walk_expression_statement(self, it);
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        if let Expression::ThisExpression(this_expression) = &it.object {
            self.check_s2990_this_expression(this_expression);
        }
        walk_static_member_expression(self, it);
    }

    fn visit_computed_member_expression(&mut self, it: &ComputedMemberExpression<'a>) {
        if let Expression::ThisExpression(this_expression) = &it.object {
            self.check_s2990_this_expression(this_expression);
        }
        walk_computed_member_expression(self, it);
    }

    fn visit_class(&mut self, it: &oxc_ast::ast::Class<'a>) {
        self.class_depth += 1;
        walk_class(self, it);
        self.class_depth -= 1;
    }

    fn visit_ts_module_block(&mut self, it: &oxc_ast::ast::TSModuleBlock<'a>) {
        self.ts_module_depth += 1;
        walk_ts_module_block(self, it);
        self.ts_module_depth -= 1;
    }

    fn visit_function(&mut self, it: &oxc_ast::ast::Function<'a>, flags: ScopeFlags) {
        // Regular functions create a new `this` binding; arrows do not, so
        // block-bodied arrows must not raise the depth (`S2990` treats
        // top-level-arrow `this` as the global `this`).
        self.function_depth += 1;
        walk_function(self, it, flags);
        self.function_depth -= 1;
    }

    fn visit_function_body(&mut self, it: &oxc_ast::ast::FunctionBody<'a>) {
        self.check_s1539_function_body(it);
        walk_function_body(self, it);
    }
}

/// Case- and separator-insensitive form used to compare declared names with
/// file names.
fn normalized_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Declared name of a default export, if it is statically knowable.
fn default_export_name<'a>(program: &'a oxc_ast::ast::Program<'a>) -> Option<(&'a str, Span)> {
    for statement in &program.body {
        let Statement::ExportDefaultDeclaration(export) = statement else {
            continue;
        };
        return match &export.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                let id = function.id.as_ref()?;
                Some((&id.name, export.span()))
            }
            ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                let id = class.id.as_ref()?;
                Some((&id.name, export.span()))
            }
            _ => {
                if let Some(expression) = export.declaration.as_expression() {
                    match unparenthesized(expression) {
                        Expression::Identifier(identifier) => {
                            Some((&identifier.name, export.span()))
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
        };
    }
    None
}

/// `S3317`: the default-exported name should echo the file stem.
pub(crate) fn check_default_export_name(
    program: &oxc_ast::ast::Program<'_>,
    path: &Path,
    _index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return issues;
    };
    if let Some((name, _)) = default_export_name(program)
        && normalized_name(name) != normalized_name(stem)
    {
        issues.push(Issue {
            rule_key: format!("{}:S3317", language.prefix()),
            message: format!("Rename this file to \"{name}\""),
            range: hoonarqube_ir::Range::file_level(),
            fix: None,
            flows: Vec::new(),
            alternatives: Vec::new(),
        });
    }
    issues
}

/// Lexically normalized form of `path`: `.` segments dropped and `..`
/// segments resolved against the preceding normal component, without
/// touching the filesystem. `..` segments that escape the path's own root
/// are preserved so relative paths stay comparable.
fn normalized_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_)) => {
                    normalized.pop();
                }
                Some(Component::RootDir) => {}
                _ => normalized.push(".."),
            },
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

/// `specifier` interpreted as a module path relative to `importing_file`,
/// compared extension-insensitively so `./x` matches `x.ts`/`x.js` siblings.
/// A trailing directory specifier also matches the file's `index` module.
fn relative_specifier_resolves_to_self(specifier: &str, importing_file: &Path) -> bool {
    let relative = specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier == "."
        || specifier == "..";
    if !relative {
        return false;
    }
    let directory = importing_file.parent().unwrap_or_else(|| Path::new(""));
    let resolved = normalized_lexical(&directory.join(specifier));
    let target = normalized_lexical(importing_file);
    let target_extensionless = target.with_extension("");
    resolved.with_extension("") == target_extensionless
        || resolved.join("index").with_extension("") == target_extensionless
}

/// `S7060`: imports whose specifier resolves to the importing file itself.
/// Only relative specifiers (`./`, `../`, `.`, `..`) can resolve to the
/// importing file; bare package specifiers such as `@playwright/test` name
/// external packages and are never self-imports.
pub(crate) fn check_self_imports(
    program: &oxc_ast::ast::Program<'_>,
    path: &Path,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in &program.body {
        if let Statement::ImportDeclaration(import) = statement
            && relative_specifier_resolves_to_self(&import.source.value, path)
        {
            issues.push(span_issue(
                index,
                format!("{}:S7060", language.prefix()),
                "Remove this import: the module resolves to the importing file itself.",
                import.span(),
            ));
        }
    }
    issues
}

impl<'a> Visit<'a> for TestFrameworkCollector<'_, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_skipped_or_focused(it);
        self.check_this_timeout_zero(it);
        self.check_test_callback(it);
        self.check_expect_call(it);
        self.check_throw_assertion_type(it);
        if let Some(name) = callee_name(it)
            && TEST_FRAMEWORK_GLOBALS.contains(&name)
        {
            self.test_calls_found = true;
        }
        walk_call_expression(self, it);
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        self.check_incomplete_chai_chain(&it.expression);
        walk_expression_statement(self, it);
    }

    fn visit_catch_clause(&mut self, it: &oxc_ast::ast::CatchClause<'a>) {
        self.check_catch_without_assertion(it);
        walk_catch_clause(self, it);
    }
}

impl TestFrameworkCollector<'_, '_> {
    /// Whether the raw body text contains `needle`, ASCII
    /// case-insensitively. Equivalent to the former
    /// `body_text(span).contains(needle)` over a lowercased copy — the
    /// ASCII lowercase map is byte-position preserving — without
    /// materializing a lowered copy of the whole body per query.
    pub(crate) fn body_contains(&self, span: Span, needle: &str) -> bool {
        crate::support::contains_ascii_case_insensitive(
            span_text(self.source, span).as_bytes(),
            needle.as_bytes(),
        )
    }

    /// Raw body text of `span` (no copy).
    pub(crate) fn body_source(&self, span: Span) -> &str {
        span_text(self.source, span)
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::*;

    #[test]
    fn encryption_api_usage_is_a_hotspot() {
        let violating = js_keys("const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);\n");
        assert_eq!(count_key(&violating, "javascript:S4787"), 1);

        let clean = js_keys("const digest = crypto.createHash('sha256');\n");
        assert_eq!(count_key(&clean, "javascript:S4787"), 0);
    }

    #[test]
    fn bare_tls_version_data_is_not_a_protocol_setting() {
        let findings = js_keys("const version = 'TLSv1';\nconst older = 'TLSv1.1';\n");
        assert_eq!(count_key(&findings, "javascript:S4423"), 0);

        let clean = js_keys("const version = 'TLSv1.2';\n");
        assert_eq!(count_key(&clean, "javascript:S4423"), 0);
    }

    #[test]
    fn weak_key_generation_parameters_are_flagged() {
        let curve = js_keys("const dh = crypto.createECDH('secp112r1');\n");
        assert_eq!(count_key(&curve, "javascript:S4426"), 1);

        let modulus = js_keys("crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });\n");
        assert_eq!(count_key(&modulus, "javascript:S4426"), 1);

        let strong = js_keys("const dh = crypto.createECDH('secp256k1');\n");
        assert_eq!(count_key(&strong, "javascript:S4426"), 0);
    }

    #[test]
    fn ecb_mode_and_missing_iv_are_flagged() {
        let ecb = js_keys("crypto.createCipheriv('aes-128-ecb', key, iv);\n");
        assert_eq!(count_key(&ecb, "javascript:S5542"), 1);

        let no_iv = js_keys("crypto.createCipheriv('aes-128-cbc', key, null);\n");
        assert_eq!(count_key(&no_iv, "javascript:S5542"), 1);

        // CE-parity flip: the documented scope treats CBC as insecure
        // regardless of IV; the captured engine fires on `aes-256-cbc` with
        // a zeroed Buffer.alloc(16) IV (oracle-js s5542_good.js) and co-fires
        // with S5547 on `des-ede3-cbc` (s5547_bad.js).
        let cbc_with_iv = js_keys("crypto.createCipheriv('aes-128-cbc', key, iv);\n");
        assert_eq!(count_key(&cbc_with_iv, "javascript:S5542"), 1);

        let gcm = js_keys("crypto.createCipheriv('aes-256-gcm', key, iv);\n");
        assert_eq!(count_key(&gcm, "javascript:S5542"), 0);
    }

    #[test]
    fn broken_cipher_families_are_flagged() {
        let violating = js_keys("crypto.createCipheriv('des-cbc', key, iv);\n");
        assert_eq!(count_key(&violating, "javascript:S5547"), 1);

        let clean = js_keys("crypto.createCipheriv('aes-128-cbc', key, iv);\n");
        assert_eq!(count_key(&clean, "javascript:S5547"), 0);
    }

    #[test]
    fn math_random_is_a_hotspot() {
        let findings = js_keys("const token = Math.random();\n");
        assert_eq!(count_key(&findings, "javascript:S2245"), 1);

        let clean: &str = "function random(min, max) { return min + max; }\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S2245"), 0);
    }

    #[test]
    fn weak_jwt_algorithms_are_flagged() {
        let literal = js_keys("jwt.sign(payload, secret, 'none');\n");
        assert_eq!(count_key(&literal, "javascript:S5659"), 1);

        let option = js_keys("jwt.verify(token, key, { algorithm: 'none' });\n");
        assert_eq!(count_key(&option, "javascript:S5659"), 1);

        let clean = js_keys("jwt.sign(payload, secret, { algorithm: 'rs256' });\n");
        assert_eq!(count_key(&clean, "javascript:S5659"), 0);
    }

    #[test]
    fn angular_sanitizer_bypasses_are_flagged() {
        let findings = js_keys("this.sanitizer.bypassSecurityTrustHtml(value);\n");
        assert_eq!(count_key(&findings, "javascript:S6268"), 1);

        let clean = js_keys("this.sanitizer.sanitize(value);\n");
        assert_eq!(count_key(&clean, "javascript:S6268"), 0);
    }

    #[test]
    fn message_handlers_without_origin_check_are_flagged() {
        let findings = js_keys(
            "window.addEventListener('message', (event) => {\n  handle(event.data);\n});\n",
        );
        assert_eq!(count_key(&findings, "javascript:S2819"), 1);

        let checked = js_keys(
            "window.onmessage = (event) => {\n  if (event.origin !== 'https://a') return;\n  handle(event.data);\n};\n",
        );
        assert_eq!(count_key(&checked, "javascript:S2819"), 0);
    }

    #[test]
    fn window_open_features_require_noopener() {
        let violating = js_keys("window.open(url, '_blank', 'width=200');\n");
        assert_eq!(count_key(&violating, "javascript:S5148"), 1);

        let clean = js_keys("window.open(url, '_blank', 'noopener');\n");
        assert_eq!(count_key(&clean, "javascript:S5148"), 0);
    }

    #[test]
    fn sensitive_console_logging_is_flagged() {
        let findings = js_keys("console.log('password', password);\n");
        assert_eq!(count_key(&findings, "javascript:S5757"), 1);

        let clean: &str = "console.log('user loaded', user);\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5757"), 0);
    }

    #[test]
    fn proxy_forwarding_is_a_hotspot_but_header_reads_are_not() {
        let findings = js_keys(
            "const { createProxyMiddleware } = require('http-proxy-middleware'); createProxyMiddleware({ target: 'http://localhost:9000', xfwd: true });\n",
        );
        assert_eq!(count_key(&findings, "javascript:S5759"), 1);

        let clean: &str = "const { createProxyMiddleware } = require('http-proxy-middleware'); createProxyMiddleware({ target: 'http://localhost:9000', xfwd: false }); const ip = req.headers['x-forwarded-for']; const agent = req.headers['user-agent'];\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5759"), 0);
    }

    #[test]
    fn sensitive_permission_access_is_flagged() {
        let findings = js_keys("const where = navigator.geolocation;\n");
        assert_eq!(count_key(&findings, "javascript:S5604"), 1);

        let clean: &str = "const storage = navigator.storage;\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5604"), 0);
    }

    #[test]
    fn unconditional_error_middleware_is_flagged() {
        let violating: &str = "const express = require('express'); const errorHandler = require('errorhandler'); const app = express(); app.use(errorHandler());\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S4507"), 1);

        let clean: &str =
            "const express = require('express'); const app = express(); app.use(router);\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S4507"), 0);
    }

    #[test]
    fn wildcard_cors_configuration_is_flagged() {
        let violating: &str = "app.use(cors({ origin: '*' }));\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S5122"), 1);

        let clean: &str = "app.use(cors({ origin: 'https://example.com' }));\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5122"), 0);
    }

    #[test]
    fn cleartext_protocols_are_flagged() {
        let imported = js_keys("import http from 'http';\n");
        assert_eq!(count_key(&imported, "javascript:S5332"), 1);

        let required = js_keys("const ws = require('ws');\n");
        assert_eq!(count_key(&required, "javascript:S5332"), 1);

        let url: &str = "fetch('http://example.com/data');\n";
        assert_eq!(count_key(&js_keys(url), "javascript:S5332"), 1);

        let clean: &str = "import https from 'https';\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5332"), 0);
    }

    #[test]
    fn global_tls_validation_disable_is_flagged() {
        let violating: &str = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S4830"), 1);

        let clean: &str = "process.env.node_env = 'production';\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S4830"), 0);
    }

    #[test]
    fn csrf_route_exemptions_are_flagged() {
        let violating: &str =
            "const csurf = require('csurf'); app.use(csurf({ ignoreRoutes: ['/webhook'] }));\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S4502"), 1);

        let clean: &str = "const csurf = require('csurf'); app.use(csurf());\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S4502"), 0);
    }

    #[test]
    fn raw_set_cookie_headers_are_hotspots() {
        let violating: &str = "res.setHeader('Set-Cookie', 'sid=1');\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S2255"), 1);

        let clean: &str = "res.setHeader('Content-Type', 'text/html');\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S2255"), 0);
    }

    #[test]
    fn multer_storage_destinations_are_controlled() {
        let direct = "const multer = require('multer'); const upload = multer({ storage: multer.diskStorage({}) });\n";
        assert_eq!(count_key(&js_keys(direct), "javascript:S2598"), 1);

        let clean: &str = "const multer = require('multer'); const upload = multer({ storage: multer.diskStorage({ destination: 'uploads/' }) });\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S2598"), 0);

        let indirect: &str = r"const multer = require('multer');
const storageOptions = {};
const storage = multer.diskStorage(storageOptions);
const options = { storage };
const upload = multer(options);
";
        assert_eq!(count_key(&js_keys(indirect), "javascript:S2598"), 1);
        assert_eq!(count_key(&ts_keys(indirect), "typescript:S2598"), 1);

        let explicit_destination: &str = r"const multer = require('multer');
const storageOptions = { destination: 'uploads/' };
const storage = multer.diskStorage(storageOptions);
const options = { storage };
const upload = multer(options);
";
        assert_eq!(
            count_key(&js_keys(explicit_destination), "javascript:S2598"),
            0
        );
        assert_eq!(
            count_key(&ts_keys(explicit_destination), "typescript:S2598"),
            0
        );

        let shadowed: &str = r"const multer = require('multer');
const options = { storage: multer.diskStorage({}) };
function configure(multer) {
    const upload = multer(options);
}
";
        assert_eq!(count_key(&js_keys(shadowed), "javascript:S2598"), 0);
        assert_eq!(count_key(&ts_keys(shadowed), "typescript:S2598"), 0);

        let unrelated_factory: &str = r"const multer = require('multer');
const options = { storage: multer.diskStorage({}) };
multer.diskStorage(options);
";
        assert_eq!(
            count_key(&js_keys(unrelated_factory), "javascript:S2598"),
            0
        );
        assert_eq!(
            count_key(&ts_keys(unrelated_factory), "typescript:S2598"),
            0
        );

        let reassigned: &str = r"const multer = require('multer');
let storage = multer.diskStorage({});
storage = otherStorage;
const options = { storage };
const upload = multer(options);
";
        assert_eq!(count_key(&js_keys(reassigned), "javascript:S2598"), 0);
        assert_eq!(count_key(&ts_keys(reassigned), "typescript:S2598"), 0);

        let unknown_options = "const multer = require('multer'); const storageOptions = configuredOptions(); const storage = multer.diskStorage(storageOptions); multer({ storage });";
        assert_eq!(count_key(&js_keys(unknown_options), "javascript:S2598"), 0);
        assert_eq!(count_key(&ts_keys(unknown_options), "typescript:S2598"), 0);

        let replaced_options = "const multer = require('multer'); let storageOptions = {}; storageOptions = configuredOptions; const storage = multer.diskStorage(storageOptions); multer({ storage });";
        assert_eq!(count_key(&js_keys(replaced_options), "javascript:S2598"), 0);
        assert_eq!(count_key(&ts_keys(replaced_options), "typescript:S2598"), 0);

        let opaque_storage = "const multer = require('multer'); const storage = multer.diskStorage({ ...configuredOptions }); multer({ storage });";
        assert_eq!(count_key(&js_keys(opaque_storage), "javascript:S2598"), 0);
        assert_eq!(count_key(&ts_keys(opaque_storage), "typescript:S2598"), 0);
    }

    #[test]
    fn xml_parsers_allowing_entity_expansion_are_flagged() {
        let violating: &str = "const libxmljs = require('libxmljs'); libxmljs.parseXmlString(xml, { noent: true, noxxe: true });\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S2755"), 1);

        let no_xxe_guard: &str = "const libxmljs = require('libxmljs'); libxmljs.parseXmlString(xml, { noent: false, noxxe: false });\n";
        assert_eq!(count_key(&js_keys(no_xxe_guard), "javascript:S2755"), 1);

        let clean: &str = "const libxmljs = require('libxmljs'); libxmljs.parseXmlString(xml, { noent: false, noxxe: true });\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S2755"), 0);
    }

    #[test]
    fn archive_extraction_is_a_hotspot() {
        let violating: &str = "zip.extractAllTo(target);\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S5042"), 1);

        let clean: &str = "zip.readFile(name);\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5042"), 0);
    }

    #[test]
    fn disabled_certificate_verification_options_are_flagged() {
        let violating: &str = "const https = require('https'); const request = https.request; request({ hostname: 'example.com', rejectUnauthorized: false });\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S5527"), 1);

        let clean: &str = "const https = require('https'); const request = https.request; request({ hostname: 'example.com', rejectUnauthorized: true });\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5527"), 0);
    }

    #[test]
    fn autoescaping_must_stay_enabled() {
        let violating: &str = "nunjucks.configure({ autoescape: false });\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S5247"), 1);

        let clean: &str = "nunjucks.configure({ autoescape: true });\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5247"), 0);
    }

    #[test]
    fn serving_dotfiles_is_flagged() {
        let violating: &str = "express.static('public', { dotfiles: 'allow' });\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S5691"), 1);

        let clean: &str = "express.static('public', { dotfiles: 'ignore' });\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5691"), 0);
    }

    #[test]
    fn body_parsers_respect_explicit_and_default_size_limits() {
        let violating: &str =
            "const express = require('express'); const parser = express.json({ limit: '4mb' });\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S5693"), 1);

        let clean: &str = "const express = require('express'); const parser = express.json({ limit: '100kb' });\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5693"), 0);

        let default_limit =
            "const express = require('express'); const parser = express.json({ strict: true });\n";
        assert_eq!(count_key(&js_keys(default_limit), "javascript:S5693"), 0);

        let unbound = "app.use(express.json({ strict: true }));\n";
        assert_eq!(count_key(&js_keys(unbound), "javascript:S5693"), 0);
    }

    #[test]
    fn helmet_csp_disabling_is_flagged_only_when_mounted() {
        let entire: &str = "const express = require('express'); const helmet = require('helmet'); const app = express(); app.use(helmet({ contentSecurityPolicy: false }));\n";
        let report = js(entire);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S5728")
            .expect("mounted Helmet CSP should be reported");
        assert_eq!(
            issue.message,
            "Make sure not enabling content security policy fetch directives is safe here."
        );
        assert_eq!(count_key(&report_keys(&report), "javascript:S5728"), 1);

        let unused: &str =
            "const helmet = require('helmet'); helmet({ contentSecurityPolicy: false });\n";
        assert_eq!(count_key(&js_keys(unused), "javascript:S5728"), 0);

        let directive: &str = "const express = require('express'); const helmet = require('helmet'); const app = express(); app.use(helmet({ contentSecurityPolicy: { directives: { scriptSrc: [] } } }));\n";
        assert_eq!(count_key(&js_keys(directive), "javascript:S5728"), 0);

        let clean: &str = "const express = require('express'); const helmet = require('helmet'); const app = express(); app.use(helmet({ contentSecurityPolicy: { directives: { scriptSrc: [\"'self'\"] } } }));\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5728"), 0);
    }

    #[test]
    fn helmet_csp_reused_middleware_reports_each_mount() {
        let report = js(
            "const express = require('express');\nconst helmet = require('helmet');\nconst app = express();\nconst middleware = helmet({ contentSecurityPolicy: false });\napp.use('/a', middleware);\napp.use('/b', middleware);\n",
        );
        let lines: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S5728")
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(lines, vec![5, 6]);
    }

    #[test]
    fn helmet_csp_resolves_array_values_but_not_rebound_middleware() {
        let array = "const express = require('express'); const helmet = require('helmet'); const app = express(); const middleware = [helmet({ contentSecurityPolicy: false })]; app.use(middleware);\n";
        assert_eq!(count_key(&js_keys(array), "javascript:S5728"), 1);

        let rebound = "const express = require('express'); const helmet = require('helmet'); const app = express(); let middleware = helmet({ contentSecurityPolicy: false }); middleware = () => {}; app.use(middleware);\n";
        assert_eq!(count_key(&js_keys(rebound), "javascript:S5728"), 0);
    }

    #[test]
    fn command_line_arguments_are_hotspots() {
        let indexed: &str = "const first = process.argv[2];\n";
        assert_eq!(count_key(&js_keys(indexed), "javascript:S4823"), 1);

        let exec_argv: &str = "if (process.execArgv.length > 0) {}\n";
        assert_eq!(count_key(&js_keys(exec_argv), "javascript:S4823"), 1);

        let clean: &str = "const mode = process.env.NODE_ENV;\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S4823"), 0);
    }

    #[test]
    fn standard_input_reads_are_hotspots() {
        let violating: &str = "process.stdin.on('data', handler);\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S4829"), 1);

        let clean: &str = "console.log(process.stdout.isTTY);\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S4829"), 0);
    }

    #[test]
    fn xpath_evaluation_is_a_hotspot() {
        let evaluate: &str = "const node = document.evaluate(expr, ctx);\n";
        assert_eq!(count_key(&js_keys(evaluate), "javascript:S4817"), 1);

        let evaluator: &str = "const evaluator = new XPathEvaluator();\n";
        assert_eq!(count_key(&js_keys(evaluator), "javascript:S4817"), 1);

        let imported: &str = "import { evaluate } from 'xpath';\n";
        assert_eq!(count_key(&js_keys(imported), "javascript:S4817"), 1);

        let required: &str =
            "const xpath = require('xpath');\nconst nodes = xpath.select(expr, doc);\n";
        assert_eq!(count_key(&js_keys(required), "javascript:S4817"), 1);

        let clean: &str = "const score = evaluateAnswer(answer);\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S4817"), 0);
    }

    #[test]
    fn raw_sockets_are_hotspots() {
        let imported: &str = "import * as net from 'net';\n";
        assert_eq!(count_key(&js_keys(imported), "javascript:S4818"), 1);

        let required: &str = "const dgram = require('dgram');\n";
        assert_eq!(count_key(&js_keys(required), "javascript:S4818"), 1);

        let constructed: &str = "const socket = new net.Socket();\n";
        assert_eq!(count_key(&js_keys(constructed), "javascript:S4818"), 1);

        let clean: &str = "import http from 'http';\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S4818"), 0);
    }

    #[test]
    fn certificate_transparency_disabling_is_flagged() {
        let header: &str = "res.setHeader('Expect-CT', 'max-age=0');\n";
        assert_eq!(count_key(&js_keys(header), "javascript:S5742"), 1);

        let helmet: &str = "app.use(helmet({ expectCt: false }));\n";
        assert_eq!(count_key(&js_keys(helmet), "javascript:S5742"), 1);

        let enforcing: &str = "res.setHeader('Expect-CT', 'max-age=86400, enforce');\n";
        assert_eq!(count_key(&js_keys(enforcing), "javascript:S5742"), 0);
    }

    #[test]
    fn dns_prefetch_control_is_flagged() {
        let header: &str = "res.setHeader('X-DNS-Prefetch-Control', 'on');\n";
        assert_eq!(count_key(&js_keys(header), "javascript:S5743"), 1);

        let helmet: &str = "app.use(helmet({ dnsPrefetch: false }));\n";
        assert_eq!(count_key(&js_keys(helmet), "javascript:S5743"), 1);

        let written: &str = "res.writeHead(200, { 'X-DNS-Prefetch-Control': 'on' });\n";
        assert_eq!(count_key(&js_keys(written), "javascript:S5743"), 1);

        let clean: &str = "res.setHeader('X-DNS-Prefetch-Control', 'off');\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5743"), 0);
    }

    #[test]
    fn test_callbacks_need_assertions() {
        let without: &str = "it('calls home', () => { home.call(); });\n";
        assert_eq!(count_key(&test_file_keys(without), "javascript:S2699"), 1);

        let with: &str = "it('calls home', () => { expect(home.calls).to.equal(1); });\n";
        assert_eq!(count_key(&test_file_keys(with), "javascript:S2699"), 0);
    }

    #[test]
    fn incomplete_chai_chains_are_flagged() {
        let incomplete: &str = "expect(value).to.be;\n";
        assert_eq!(
            count_key(&test_file_keys(incomplete), "javascript:S2970"),
            1
        );

        let complete: &str = "expect(value).to.be.true;\n";
        assert_eq!(count_key(&test_file_keys(complete), "javascript:S2970"), 0);
    }

    #[test]
    fn swapped_chai_arguments_are_flagged() {
        let swapped: &str = "expect(5).to.equal(result);\n";
        assert_eq!(count_key(&test_file_keys(swapped), "javascript:S3415"), 1);

        let natural: &str = "expect(result).to.equal(5);\n";
        assert_eq!(count_key(&test_file_keys(natural), "javascript:S3415"), 0);
    }

    #[test]
    fn self_comparing_assertions_are_flagged() {
        let same_value: &str = "expect(value).to.equal(value);\n";
        assert_eq!(
            count_key(&test_file_keys(same_value), "javascript:S5863"),
            1
        );

        let other: &str = "expect(value).to.equal(other);\n";
        assert_eq!(count_key(&test_file_keys(other), "javascript:S5863"), 0);
    }

    #[test]
    fn catch_blocks_without_assertions_are_flagged() {
        let without: &str = "it('throws', () => {\n  try {\n    boom();\n  } catch (error) {\n    log(error);\n  }\n});\n";
        assert_eq!(count_key(&test_file_keys(without), "javascript:S5958"), 1);

        let with: &str = "it('throws', () => {\n  try {\n    boom();\n  } catch (error) {\n    expect(error).to.match(/bad/);\n  }\n});\n";
        assert_eq!(count_key(&test_file_keys(with), "javascript:S5958"), 0);
    }

    #[test]
    fn nondeterministic_test_values_are_flagged() {
        let random: &str = "it('rolls', () => {\n  const roll = Math.random();\n  expect(roll).to.be.a('number');\n});\n";
        assert_eq!(count_key(&test_file_keys(random), "javascript:S5973"), 1);

        let fixed: &str =
            "it('rolls', () => {\n  const roll = 4;\n  expect(roll).to.equal(4);\n});\n";
        assert_eq!(count_key(&test_file_keys(fixed), "javascript:S5973"), 0);
    }

    #[test]
    fn statements_after_done_are_flagged() {
        let after: &str =
            "it('finishes', function (done) {\n  run(done);\n  done();\n  verify();\n});\n";
        assert_eq!(count_key(&test_file_keys(after), "javascript:S6079"), 1);

        let last: &str = "it('finishes', function (done) {\n  verify();\n  done();\n});\n";
        assert_eq!(count_key(&test_file_keys(last), "javascript:S6079"), 0);
    }

    #[test]
    fn batch5_ascii_case_insensitive_checks_match_baseline() {
        // ASCII-only case-insensitive body scans: `MATH.RANDOM()`,
        // `DONE()`, `EXPECT(...)`, and `PASSWORD` all behave exactly like
        // their lowercase forms (baseline-verified).
        let upper_random: &str = "it('rolls', () => { MATH.RANDOM(); });\n";
        assert_eq!(
            count_key(&test_file_keys(upper_random), "javascript:S5973"),
            1
        );

        let upper_done: &str = "it('finishes', function (done) { DONE(); verify(); });\n";
        assert_eq!(
            count_key(&test_file_keys(upper_done), "javascript:S6079"),
            1
        );

        let upper_expect: &str = "it('throws', () => {\n  try {\n    boom();\n  } catch (e) {\n    EXPECT(e);\n  }\n});\n";
        assert_eq!(
            count_key(&test_file_keys(upper_expect), "javascript:S5958"),
            0
        );

        let upper_secret: &str = "console.log(\"user PASSWORD x\");\n";
        assert_eq!(count_key(&js_keys(upper_secret), "javascript:S5757"), 1);
        let plain: &str = "console.log(\"plain\");\n";
        assert_eq!(count_key(&js_keys(plain), "javascript:S5757"), 0);
    }

    #[test]
    fn disabled_timeouts_are_flagged() {
        let disabled: &str = "describe('slow', () => {\n  this.timeout(0);\n});\n";
        assert_eq!(count_key(&test_file_keys(disabled), "javascript:S6080"), 1);

        let limited: &str = "describe('slow', () => {\n  this.timeout(2000);\n});\n";
        assert_eq!(count_key(&test_file_keys(limited), "javascript:S6080"), 0);
    }

    #[test]
    fn multi_matcher_chains_are_flagged() {
        let chained: &str = "expect(value).to.equal(1).and.equal(2);\n";
        assert_eq!(count_key(&test_file_keys(chained), "javascript:S6092"), 1);

        let single: &str = "expect(value).to.equal(1);\n";
        assert_eq!(count_key(&test_file_keys(single), "javascript:S6092"), 0);
    }

    #[test]
    fn vue_v_html_bypasses_escaping() {
        let violating: &str = "const tpl = `<div v-html=\"userContent\"></div>`;\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S6299"), 1);

        let sfc: &str = "const template = '<span v-html=raw></span>';\n";
        assert_eq!(count_key(&js_keys(sfc), "javascript:S6299"), 1);

        let clean: &str = "const tpl = `<div>{{ userContent }}</div>`;\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S6299"), 0);
    }

    #[test]
    fn s3_buckets_need_server_side_encryption() {
        let violating: &str = "const result = await s3.createBucket({ Bucket: 'name' });\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S6245"), 1);

        let command: &str = "await client.send(new CreateBucketCommand({ Bucket: 'name' }));\n";
        assert_eq!(count_key(&js_keys(command), "javascript:S6245"), 1);

        let encrypted: &str = "const r = await s3.createBucket({ Bucket: 'n', ServerSideEncryptionConfiguration: {} });\n";
        assert_eq!(count_key(&js_keys(encrypted), "javascript:S6245"), 0);
    }

    #[test]
    fn top_level_var_and_function_declarations_are_flagged() {
        let globals: &str = "var counter = 1;\nfunction reset() {}\n";
        let javascript = js_keys(globals);
        assert_eq!(count_key(&javascript, "javascript:S3798"), 2);

        let typescript = ts_keys(globals);
        assert_eq!(count_key(&typescript, "typescript:S3798"), 0);
    }

    #[test]
    fn misplaced_use_strict_is_flagged() {
        let misplaced: &str = "console.log(1);\n'use strict';\n";
        assert_eq!(count_key(&js_keys(misplaced), "javascript:S1539"), 1);

        let prologue: &str = "'use strict';\nconsole.log(1);\n";
        assert_eq!(count_key(&js_keys(prologue), "javascript:S1539"), 0);
    }

    #[test]
    fn global_this_expressions_are_flagged() {
        let top_level: &str = "console.log(this.value);\n";
        assert_eq!(count_key(&js_keys(top_level), "javascript:S2990"), 1);

        let in_function: &str = "function f() { return this.value; }\n";
        assert_eq!(count_key(&js_keys(in_function), "javascript:S2990"), 0);

        // Arrows do not bind `this`: a block-bodied top-level arrow's `this`
        // is still the global/module `this` and must be flagged.
        let in_top_level_arrow: &str = "const f = () => { console.log(this.value); }\n";
        assert_eq!(
            count_key(&js_keys(in_top_level_arrow), "javascript:S2990"),
            1
        );

        let in_nested_regular_function_of_arrow: &str =
            "const f = () => { (function () { return this.value; }); }\n";
        assert_eq!(
            count_key(
                &js_keys(in_nested_regular_function_of_arrow),
                "javascript:S2990"
            ),
            0
        );
    }

    #[test]
    fn default_export_names_should_match_file_stems() {
        let mismatched = analyze(
            PathBuf::from("user-service.js"),
            "export default class Account {}\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            count_key(&mismatched_keys(&mismatched), "javascript:S3317"),
            1
        );

        let matched = analyze(
            PathBuf::from("user-service.js"),
            "export default class UserService {}\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&matched_keys(&matched), "javascript:S3317"), 0);
    }

    #[test]
    fn self_imports_are_flagged() {
        let self_import = analyze(
            PathBuf::from("app.js"),
            "import './app';\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        let findings: Vec<_> = self_import
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7060")
            .collect();
        assert_eq!(findings.len(), 1);

        let other_import = analyze(
            PathBuf::from("app.js"),
            "import './other';\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert!(
            other_import
                .issues
                .iter()
                .all(|issue| issue.rule_key != "javascript:S7060")
        );

        // A `..` specifier that climbs back to the importing file is still a
        // genuine self-import.
        let parent_self_import = analyze(
            PathBuf::from("sub/app.js"),
            "import '../sub/app';\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            count_key(&report_keys(&parent_self_import), "javascript:S7060"),
            1
        );

        // A directory specifier resolves through its `index` module.
        let index_self_import = analyze(
            PathBuf::from("pkg/index.js"),
            "import './';\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            index_self_import
                .issues
                .iter()
                .filter(|issue| issue.rule_key == "javascript:S7060")
                .count(),
            1
        );
    }

    #[test]
    fn package_specifiers_are_never_self_imports() {
        // #790: a bare package specifier resolves through the package
        // registry, not the importing file's directory, even when its final
        // path segment matches the importing file's stem.
        for specifier in ["@playwright/test", "test", "lodash/test", "@scope/sub/test"] {
            let report = analyze(
                PathBuf::from("test.ts"),
                &format!("import {{ expect }} from \"{specifier}\";\nexpect(1);\n"),
                JstsLanguage::TypeScript,
                &AnalyzerOptions::default(),
            );
            assert!(
                report
                    .issues
                    .iter()
                    .all(|issue| issue.rule_key != "typescript:S7060"),
                "{specifier} must not be treated as a self-import"
            );
        }

        // A relative specifier whose basename matches but resolves to a
        // different file is not a self-import either.
        let sibling = analyze(
            PathBuf::from("test.ts"),
            "import './sub/test';\n",
            JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        );
        assert!(
            sibling
                .issues
                .iter()
                .all(|issue| issue.rule_key != "typescript:S7060")
        );
    }
}
