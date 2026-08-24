// Family walker for 'batch5' (generated).
use super::s2187_test_framework_rules::check_test_framework_rules;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex};
use crate::{
    JstsLanguage, MiscCollector, SecurityHotspotCollector, TsTypeCollector,
    check_default_export_name, check_self_imports,
};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;
use std::path::Path;

// --- Batch5: TypeScript-only AST rules, security hotspots, test-framework
// --- rules, and misc Tier A ---

/// Entry point for all Batch5 rules; fans out into the per-section checks.
pub(crate) fn check_batch5_rules<'a>(
    path: &'a Path,
    program: &'a oxc_ast::ast::Program<'a>,
    source: &'a str,
    index: &'a LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_ts_type_rules(program, source, index, language));
    issues.extend(check_security_hotspot_rules(
        program, source, index, language,
    ));
    if is_test_file(path) {
        issues.extend(check_test_framework_rules(program, source, index, language));
    }
    issues.extend(check_misc_rules(path, program, index, language));
    issues
}

/// All Batch5 TypeScript-only type-system rules in one traversal.
pub(crate) fn check_ts_type_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = TsTypeCollector {
        source,
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        class_stack: Vec::new(),
        constructor_depth: 0,
        try_guard_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// All Batch5 security-hotspot rules in one traversal.
pub(crate) fn check_security_hotspot_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = SecurityHotspotCollector {
        source,
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Whether `path` looks like a test file (`foo.test.js`, `foo.spec.ts`, or
/// anywhere under a `__tests__` directory).
pub(crate) fn is_test_file(path: &Path) -> bool {
    let stem_is_test =
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| match stem.rsplit_once('.') {
                Some((_, extension)) => {
                    matches!(extension.to_ascii_lowercase().as_str(), "test" | "spec")
                }
                None => false,
            });
    let in_tests_dir = path
        .components()
        .any(|component| component.as_os_str() == "__tests__");
    stem_is_test || in_tests_dir
}

/// All Batch5 misc Tier-A rules in one pass.
pub(crate) fn check_misc_rules(
    path: &Path,
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = MiscCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        function_depth: 0,
    };
    collector.visit_program(program);
    let mut issues = collector.sink.issues;
    issues.extend(check_default_export_name(program, path, index, language));
    issues.extend(check_self_imports(program, path, index, language));
    issues
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_batch5_rules(ctx.path, ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn computed_enum_members_are_flagged() {
        let violating = ts_keys("enum E { A = getValue(), B = 1 }\n");
        assert_eq!(count_key(&violating, "typescript:S6550"), 1);

        let clean = ts_keys("enum E { A = 1, B = -2, C = 'x', D }\n");
        assert_eq!(count_key(&clean, "typescript:S6550"), 0);
    }

    #[test]
    fn enums_mixing_initialized_members_are_flagged() {
        let mixed = ts_keys("enum E { A = 1, B, C = 3 }\n");
        assert_eq!(count_key(&mixed, "typescript:S6572"), 1);

        let uniform_initialized = ts_keys("enum E { A = 1, B = 2 }\n");
        assert_eq!(count_key(&uniform_initialized, "typescript:S6572"), 0);

        let uniform_implicit = ts_keys("enum E { A, B }\n");
        assert_eq!(count_key(&uniform_implicit, "typescript:S6572"), 0);
    }

    #[test]
    fn duplicate_enum_values_are_flagged() {
        let duplicates = ts_keys("enum E { A = 1, B = 1, C = 'x', D = 'x' }\n");
        assert_eq!(count_key(&duplicates, "typescript:S6578"), 2);

        let unique = ts_keys("enum E { A = 1, B = 2, C = 'x' }\n");
        assert_eq!(count_key(&unique, "typescript:S6578"), 0);
    }

    #[test]
    fn enums_mixing_value_kinds_are_flagged() {
        let mixed = ts_keys("enum E { A = 1, B = 'x' }\n");
        assert_eq!(count_key(&mixed, "typescript:S6583"), 1);

        let numeric_only = ts_keys("enum E { A = 1, B = 2 }\n");
        assert_eq!(count_key(&numeric_only, "typescript:S6583"), 0);

        let text_only = ts_keys("enum E { A = 'x', B = 'y' }\n");
        assert_eq!(count_key(&text_only, "typescript:S6583"), 0);
    }

    #[test]
    fn redundant_union_and_intersection_members_are_flagged() {
        let keywords = ts_keys("type T = string | number | string;\n");
        assert_eq!(count_key(&keywords, "typescript:S6571"), 1);

        let subsumed = ts_keys("type T = string | 'literal';\n");
        assert_eq!(count_key(&subsumed, "typescript:S6571"), 1);

        let clean = ts_keys("type T = string | number;\n");
        assert_eq!(count_key(&clean, "typescript:S6571"), 0);
    }

    #[test]
    fn structurally_equal_type_members_are_flagged() {
        let duplicate_objects = ts_keys("type T = { a: string } | { a: string };\n");
        assert_eq!(count_key(&duplicate_objects, "typescript:S4621"), 1);

        let distinct_objects = ts_keys("type T = { a: string } | { b: string };\n");
        assert_eq!(count_key(&distinct_objects, "typescript:S4621"), 0);
    }

    #[test]
    fn oversized_unions_are_flagged() {
        let oversized = ts_keys("type T = 'a' | 'b' | 'c' | 'd';\n");
        assert_eq!(count_key(&oversized, "typescript:S4622"), 1);

        let compact = ts_keys("type T = 'a' | 'b' | 'c';\n");
        assert_eq!(count_key(&compact, "typescript:S4622"), 0);
    }

    #[test]
    fn meaningless_intersections_are_flagged() {
        let meaningless = ts_keys("type T = string & { a: number };\n");
        assert_eq!(count_key(&meaningless, "typescript:S4335"), 1);

        let branded =
            ts_keys("type Brand = { brand: 'id' };\ntype Tagged = Brand & { v: number };\n");
        assert_eq!(count_key(&branded, "typescript:S4335"), 0);
    }

    #[test]
    fn alias_to_bare_reference_is_flagged() {
        let alias_chain = ts_keys("type A = { x: number };\ntype B = A;\n");
        assert_eq!(count_key(&alias_chain, "typescript:S6564"), 1);

        let concrete = ts_keys("type B = { x: number };\n");
        assert_eq!(count_key(&concrete, "typescript:S6564"), 0);

        let generic_reference = ts_keys("type Mapping = Record<string, number>;\n");
        assert_eq!(count_key(&generic_reference, "typescript:S6564"), 0);
    }

    #[test]
    fn useless_generic_constraints_are_flagged() {
        let constrained = ts_keys("function f<T extends unknown>(x: T) { return x; }\n");
        assert_eq!(count_key(&constrained, "typescript:S6569"), 1);

        let unconstrained = ts_keys("function f<T>(x: T) { return x; }\n");
        assert_eq!(count_key(&unconstrained, "typescript:S6569"), 0);

        let meaningful = ts_keys("function f<T extends { id: number }>(x: T) { return x; }\n");
        assert_eq!(count_key(&meaningful, "typescript:S6569"), 0);
    }

    #[test]
    fn typescript_only_type_rules_never_fire_for_javascript() {
        let findings = js_keys("type T = string | number | string;\nenum E { A = 1, B = 1 }\n");
        for key in ["javascript:S6550", "javascript:S6571", "javascript:S6578"] {
            assert_eq!(count_key(&findings, key), 0, "{key}");
        }
    }

    #[test]
    fn non_null_assertions_are_flagged() {
        let violating = ts_keys("const x = value!;\n");
        assert_eq!(count_key(&violating, "typescript:S2966"), 1);

        let clean = ts_keys("const x = value;\n");
        assert_eq!(count_key(&clean, "typescript:S2966"), 0);
    }

    #[test]
    fn primitive_annotations_with_initializers_are_flagged() {
        let violating = ts_keys("const X: number = 1;\nlet y: string = 'a';\n");
        assert_eq!(count_key(&violating, "typescript:S3257"), 2);

        let without_initializer = ts_keys("let y: string;\n");
        assert_eq!(count_key(&without_initializer, "typescript:S3257"), 0);

        let non_primitive = ts_keys("const P: Point = { x: 1, y: 2 };\n");
        assert_eq!(count_key(&non_primitive, "typescript:S3257"), 0);
    }

    #[test]
    fn angle_bracket_assertions_are_flagged() {
        let violating = ts_keys("const x = <string>value;\n");
        assert_eq!(count_key(&violating, "typescript:S4137"), 1);

        let clean = ts_keys("const x = value as string;\n");
        assert_eq!(count_key(&clean, "typescript:S4137"), 0);
    }

    #[test]
    fn module_keyword_is_flagged_over_namespace() {
        let violating = ts_keys("module Legacy { export const x = 1; }\n");
        assert_eq!(count_key(&violating, "typescript:S4156"), 1);

        let clean = ts_keys("namespace Modern { export const x = 1; }\n");
        assert_eq!(count_key(&clean, "typescript:S4156"), 0);
    }

    #[test]
    fn redundant_type_parameter_defaults_are_flagged() {
        let violating = ts_keys("function f<T extends string = string>(x: T) { return x; }\n");
        assert_eq!(count_key(&violating, "typescript:S4157"), 1);

        let distinct_default =
            ts_keys("function f<T extends object = { id: number }>(x: T) { return x; }\n");
        assert_eq!(count_key(&distinct_default, "typescript:S4157"), 0);
    }

    #[test]
    fn any_keywords_are_flagged() {
        let violating = ts_keys("let loose: any;\nfunction f(x: any) { return x; }\n");
        assert_eq!(count_key(&violating, "typescript:S4204"), 2);

        let clean = ts_keys("let tight: string;\n");
        assert_eq!(count_key(&clean, "typescript:S4204"), 0);
    }

    #[test]
    fn optional_properties_with_undefined_in_union_are_flagged() {
        let violating = ts_keys("interface P { name?: string | undefined; }\n");
        assert_eq!(count_key(&violating, "typescript:S4782"), 1);

        let required_property = ts_keys("interface P { name: string | undefined; }\n");
        assert_eq!(count_key(&required_property, "typescript:S4782"), 0);

        let optional_without_undefined = ts_keys("interface P { name?: string; }\n");
        assert_eq!(
            count_key(&optional_without_undefined, "typescript:S4782"),
            0
        );
    }

    #[test]
    fn optional_booleans_without_defaults_are_flagged() {
        let violating = ts_keys("function f(verbose?: boolean) { return verbose; }\n");
        assert_eq!(count_key(&violating, "typescript:S4798"), 1);

        let with_default = ts_keys("function f(verbose: boolean = false) { return verbose; }\n");
        assert_eq!(count_key(&with_default, "typescript:S4798"), 0);

        let optional_string = ts_keys("function f(label?: string) { return label; }\n");
        assert_eq!(count_key(&optional_string, "typescript:S4798"), 0);
    }

    #[test]
    fn single_call_signatures_become_function_types() {
        let interface_form = ts_keys("interface Handler { (event: string): void; }\n");
        assert_eq!(count_key(&interface_form, "typescript:S6598"), 1);

        let alias_form = ts_keys("type Handler = { (event: string): void };\n");
        assert_eq!(count_key(&alias_form, "typescript:S6598"), 1);

        let multi_member = ts_keys("interface Handler { (event: string): void; done: boolean; }\n");
        assert_eq!(count_key(&multi_member, "typescript:S6598"), 0);
    }

    #[test]
    fn separated_overloads_are_flagged() {
        let separated = ts_keys(
            "interface Api {\n  load(): void;\n  ready: boolean;\n  load(url: string): void;\n}\n",
        );
        assert_eq!(count_key(&separated, "typescript:S4136"), 1);

        let grouped = ts_keys(
            "interface Api {\n  load(): void;\n  load(url: string): void;\n  ready: boolean;\n}\n",
        );
        assert_eq!(count_key(&grouped, "typescript:S4136"), 0);
    }

    #[test]
    fn typescript_node_rules_never_fire_for_javascript() {
        let findings = js_keys("const x = <string>value;\nmodule M { }\nlet loose: any;\n");
        for key in ["javascript:S4137", "javascript:S4156", "javascript:S4204"] {
            assert_eq!(count_key(&findings, key), 0, "{key}");
        }
    }

    #[test]
    fn boolean_returns_suggest_type_predicates() {
        let violating = ts_keys("function isFoo(x: Foo): boolean { return true; }\n");
        assert_eq!(count_key(&violating, "typescript:S4322"), 1);

        let clean = ts_keys("function score(x: number): boolean { return x > 0; }\n");
        assert_eq!(count_key(&clean, "typescript:S4322"), 0);
    }

    #[test]
    fn wrapper_return_types_are_flagged() {
        let violating = ts_keys("function f(): Number { return 1; }\n");
        assert_eq!(count_key(&violating, "typescript:S4324"), 1);

        let clean = ts_keys("function f(): number { return 1; }\n");
        assert_eq!(count_key(&clean, "typescript:S4324"), 0);
    }

    #[test]
    fn class_typed_returns_prefer_this() {
        let violating = ts_keys("class Builder {\n  self(): Builder { return this; }\n}\n");
        assert_eq!(count_key(&violating, "typescript:S6565"), 1);

        let clean = ts_keys("class Builder {\n  build(): this { return this; }\n}\n");
        assert_eq!(count_key(&clean, "typescript:S6565"), 0);
    }

    #[test]
    fn non_null_after_guards_are_flagged() {
        let violating = ts_keys("const x = a ?? b!;\n");
        assert_eq!(count_key(&violating, "typescript:S6568"), 1);

        let clean = ts_keys("const x = a.b!;\n");
        assert_eq!(count_key(&clean, "typescript:S6568"), 0);
    }

    #[test]
    fn readonly_annotations_suggest_as_const() {
        let violating = ts_keys("const COLORS: readonly string[] = ['a', 'b'];\n");
        assert_eq!(count_key(&violating, "typescript:S6590"), 1);

        let clean = ts_keys("const MUTABLE: string[] = ['a', 'b'];\n");
        assert_eq!(count_key(&clean, "typescript:S6590"), 0);
    }

    #[test]
    fn props_interfaces_require_readonly_fields() {
        let violating = ts_keys("interface ButtonProps { label: string; size: number; }\n");
        assert_eq!(count_key(&violating, "typescript:S6759"), 2);

        let readonly = ts_keys("interface ButtonProps { readonly label: string; }\n");
        assert_eq!(count_key(&readonly, "typescript:S6759"), 0);

        let not_props = ts_keys("interface Config { label: string; }\n");
        assert_eq!(count_key(&not_props, "typescript:S6759"), 0);
    }

    #[test]
    fn static_properties_need_readonly_or_be_excluded() {
        let violating = ts_keys("class Registry { static instance = new Registry(); }\n");
        assert_eq!(count_key(&violating, "typescript:S1444"), 1);

        let readonly = ts_keys("class Registry { static readonly kind = 'reg'; }\n");
        assert_eq!(count_key(&readonly, "typescript:S1444"), 0);

        let private = ts_keys("class Registry { private static secret = 1; }\n");
        assert_eq!(count_key(&private, "typescript:S1444"), 0);
    }

    #[test]
    fn constructor_async_work_is_flagged() {
        let awaiting = ts_keys(
            "class Server {\n  constructor() {\n    const data = load();\n    void data;\n  }\n}\nasync function load() { return 1; }\n",
        );
        assert_eq!(count_key(&awaiting, "typescript:S7059"), 0);

        let direct = ts_keys(
            "class Server {\n  async load() {}\n  constructor() {\n    const p = (async () => 1)();\n    void p;\n  }\n}\n",
        );
        assert_eq!(count_key(&direct, "typescript:S7059"), 1);
    }

    #[test]
    fn nested_awaits_are_flagged_for_both_languages() {
        let typescript_findings =
            ts_keys("async function f(p: Promise<number>) { return await await p; }\n");
        assert_eq!(count_key(&typescript_findings, "typescript:S4326"), 1);

        let javascript_findings = js_keys("async function f(p) { return await await p; }\n");
        assert_eq!(count_key(&javascript_findings, "javascript:S4326"), 1);
    }

    #[test]
    fn weak_hash_algorithms_are_flagged() {
        let findings = js_keys("const hash = crypto.createHash('md5');\n");
        assert_eq!(count_key(&findings, "javascript:S2612"), 1);
        assert_eq!(count_key(&findings, "javascript:S4790"), 1);

        let strong = js_keys("const hash = crypto.createHash('sha256');\n");
        assert_eq!(count_key(&strong, "javascript:S2612"), 0);
        assert_eq!(count_key(&strong, "javascript:S4790"), 0);

        let family = js_keys("const h = crypto.createHash('ripemd160');\n");
        assert_eq!(count_key(&family, "javascript:S2612"), 0);
        assert_eq!(count_key(&family, "javascript:S4790"), 0);
    }

    #[test]
    fn shell_interpreters_and_path_lookup_are_flagged() {
        let exec = js_keys("const { exec } = require('child_process');\nexec('ls -la');\n");
        assert_eq!(count_key(&exec, "javascript:S4721"), 1);
        assert_eq!(count_key(&exec, "javascript:S4036"), 1);

        let absolute = js_keys("require('child_process').spawn('/bin/ls', ['-la']);\n");
        assert_eq!(count_key(&absolute, "javascript:S4036"), 0);
        assert_eq!(count_key(&absolute, "javascript:S4721"), 0);
    }

    #[test]
    fn cookies_require_secure_and_httponly_flags() {
        let violating: &str = "res.cookie('sid', value, { httpOnly: false });\n";
        let findings = js_keys(violating);
        assert_eq!(count_key(&findings, "javascript:S2092"), 1);
        assert_eq!(count_key(&findings, "javascript:S3330"), 1);

        let clean: &str = "res.cookie('sid', value, { secure: true, httpOnly: true });\n";
        let clean = js_keys(clean);
        assert_eq!(count_key(&clean, "javascript:S2092"), 0);
        assert_eq!(count_key(&clean, "javascript:S3330"), 0);
    }

    #[test]
    fn security_header_values_are_validated() {
        let csp: &str = "res.setHeader('Content-Security-Policy', \"default-src 'self'\");\n";
        let findings = js_keys(csp);
        assert_eq!(count_key(&findings, "javascript:S5730"), 1);
        assert_eq!(count_key(&findings, "javascript:S5732"), 1);

        let referrer: &str = "res.setHeader('Referrer-Policy', 'unsafe-url');\n";
        assert_eq!(count_key(&js_keys(referrer), "javascript:S5736"), 1);

        let hsts: &str = "res.setHeader('Strict-Transport-Security', 'max-age=0');\n";
        assert_eq!(count_key(&js_keys(hsts), "javascript:S5739"), 1);

        let nosniff: &str = "res.setHeader('X-Content-Type-Options', 'sniff');\n";
        assert_eq!(count_key(&js_keys(nosniff), "javascript:S5734"), 1);

        let powered_by: &str = "res.setHeader('X-Powered-By', 'Express');\n";
        assert_eq!(count_key(&js_keys(powered_by), "javascript:S5689"), 1);

        let clean: &str = "res.setHeader('Referrer-Policy', 'no-referrer');\n";
        assert_eq!(count_key(&js_keys(clean), "javascript:S5736"), 0);
    }

    #[test]
    fn skipped_and_focused_tests_are_flagged() {
        let skipped: &str = "xit('later', () => { expect(1).to.equal(1); });\nit.skip('also later', () => { expect(1).to.equal(1); });\n";
        let findings = test_file_keys(skipped);
        assert_eq!(count_key(&findings, "javascript:S1607"), 2);

        let focused: &str = "fit('just this', () => { expect(1).to.equal(1); });\ndescribe.only('solo', () => {});\n";
        let focused = test_file_keys(focused);

        assert_eq!(count_key(&focused, "javascript:S6426"), 2);

        let normal: &str = "it('runs', () => { expect(1).to.equal(1); });\n";
        let normal = test_file_keys(normal);
        assert_eq!(count_key(&normal, "javascript:S1607"), 0);
        assert_eq!(count_key(&normal, "javascript:S6426"), 0);
    }
}
