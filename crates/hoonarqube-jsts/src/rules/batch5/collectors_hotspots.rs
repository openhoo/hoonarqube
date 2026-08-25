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
use oxc_ast::ast::ExportDefaultDeclarationKind;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ExpressionStatement;
use oxc_ast::ast::FunctionBody;
use oxc_ast::ast::Statement;
use oxc_ast::ast::ThisExpression;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_catch_clause;
use oxc_ast_visit::walk::{
    walk_call_expression, walk_expression_statement, walk_function_body, walk_program,
    walk_this_expression,
};
use oxc_span::{GetSpan, Span};
use std::path::Path;

/// Fragments whose absence in a callback body means `S2699` flags it.
pub(crate) const ASSERTION_MARKERS: [&str; 4] = ["expect(", "assert.", "assert(", "should"];

/// Collector for the remaining single-file Tier-A checks.
pub(crate) struct MiscCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Number of enclosing function boundaries (`S2990`).
    pub(crate) function_depth: u32,
}

impl<'a> Visit<'a> for MiscCollector<'_> {
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        self.check_s3798_program(it);
        walk_program(self, it);
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        self.check_s1539_expression_statement(it);
        walk_expression_statement(self, it);
    }

    fn visit_this_expression(&mut self, it: &ThisExpression) {
        self.check_s2990_this_expression(it);
        walk_this_expression(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        // Regular functions create a new `this` binding; arrows do not.
        self.function_depth += 1;
        walk_function_body(self, it);
        self.function_depth -= 1;
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
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return issues;
    };
    if let Some((name, span)) = default_export_name(program)
        && normalized_name(name) != normalized_name(stem)
    {
        issues.push(span_issue(
            index,
            format!("{}:S3317", language.prefix()),
            format!("Rename this default export; '{name}' does not match the file name '{stem}'."),
            span,
        ));
    }
    issues
}

/// Module specifier of an import, stripped of its relative marker.
fn relative_module_stem(specifier: &str) -> Option<String> {
    let stripped = specifier.strip_prefix("./").unwrap_or(specifier);
    if stripped.starts_with('.') || specifier.starts_with('/') {
        return None;
    }
    Path::new(stripped)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(ToOwned::to_owned)
}

/// `S7060`: imports whose specifier resolves to the importing file itself.
pub(crate) fn check_self_imports(
    program: &oxc_ast::ast::Program<'_>,
    path: &Path,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let Some(self_stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return issues;
    };
    for statement in &program.body {
        if let Statement::ImportDeclaration(import) = statement
            && relative_module_stem(&import.source.value)
                .is_some_and(|stem| normalized_name(&stem) == normalized_name(self_stem))
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
    pub(crate) fn body_text(&self, span: Span) -> String {
        span_text(self.source, span).to_ascii_lowercase()
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
    fn weak_tls_protocol_versions_are_flagged() {
        let findings = js_keys("const version = 'TLSv1';\n");
        assert_eq!(count_key(&findings, "javascript:S4423"), 1);

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
    fn forwarded_header_trust_is_a_hotspot() {
        let findings = js_keys("const ip = req.headers['x-forwarded-for'];\n");
        assert_eq!(count_key(&findings, "javascript:S5759"), 1);

        let clean: &str = "const agent = req.headers['user-agent'];\n";
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
        let violating: &str = "app.use(errorHandler);\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S4507"), 1);

        let clean: &str = "app.use(router);\n";
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
        let violating: &str = "app.use(csrf({ ignoreRoutes: ['/webhook'] }));\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S4502"), 1);

        let clean: &str = "app.use(csrf());\n";
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
    fn upload_handlers_without_limits_are_flagged() {
        let call = js_keys("const upload = multer({ dest: 'uploads/' });\n");
        assert_eq!(count_key(&call, "javascript:S2598"), 1);

        let constructor = js_keys("const busboy = new Busboy({ headers: req.headers });\n");
        assert_eq!(count_key(&constructor, "javascript:S2598"), 1);

        let clean: &str = "const upload = multer({ limits: { fileSize: 1000000 } });\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S2598"), 0);
    }

    #[test]
    fn xml_parsers_allowing_entity_expansion_are_flagged() {
        let violating: &str = "libxml.parseXml(xml, { noent: true, noxxe: true });\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S2755"), 1);

        let no_xxe_guard: &str = "libxml.parseXml(xml, { noent: false });\n";
        assert_eq!(count_key(&js_keys(no_xxe_guard), "javascript:S2755"), 1);

        let clean: &str = "libxml.parseXml(xml, { noent: false, noxxe: true });\n";
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
        let violating: &str = "https.get(url, { rejectUnauthorized: false });\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S5527"), 1);

        let clean: &str = "https.get(url, { rejectUnauthorized: true });\n";
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
    fn body_parsers_need_size_limits() {
        let violating: &str = "app.use(express.json({ strict: true }));\n";
        assert_eq!(count_key(&js_keys(violating), "javascript:S5693"), 1);

        let clean: &str = "app.use(express.json({ limit: '100kb' }));\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5693"), 0);
    }

    #[test]
    fn helmet_csp_disabling_is_flagged() {
        let entire: &str = "app.use(helmet({ contentSecurityPolicy: false }));\n";
        assert_eq!(count_key(&js_keys(entire), "javascript:S5728"), 1);

        let directive: &str =
            "app.use(helmet({ contentSecurityPolicy: { directives: { scriptSrc: [] } } }));\n";
        assert_eq!(count_key(&js_keys(directive), "javascript:S5728"), 1);

        let clean: &str = "app.use(helmet({ contentSecurityPolicy: { directives: { scriptSrc: [\"'self'\"] } } }));\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5728"), 0);
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

        let required: &str = "const xpath = require('xpath');\n";
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
        let top_level: &str = "console.log(this);
";
        assert_eq!(count_key(&js_keys(top_level), "javascript:S2990"), 1);

        let in_function: &str = "function f() { return this; }\n";
        assert_eq!(count_key(&js_keys(in_function), "javascript:S2990"), 0);
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
    }
}
