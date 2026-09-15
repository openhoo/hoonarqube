// Rule module s7772_prefer_node_protocol (generated).
//
// `javascript:S7772` + `typescript:S7772` — Node.js built-in modules should
// be imported using the "node:" protocol. Reference semantics:
// eslint-plugin-unicorn `prefer-node-protocol` at the version pinned by
// SonarJS 13.x (v65.0.1, wrapped by SonarJS S7772): every module specifier
// that is a Node.js built-in without the `node:` prefix is reported in
//
// - `import ... from 'fs'` and bare `import 'fs'` (source of
//   ImportDeclaration),
// - `export ... from 'fs'` (source of ExportNamedDeclaration),
// - dynamic `import('fs')` (ImportExpression),
// - TypeScript `type Fs = import('fs')` (TSImportType),
// - `require('fs')` (static require: `require` callee, single literal
//   argument),
// - `process.getBuiltinModule('fs')`,
//
// when the specifier resolves as a built-in both with and without the
// prefix (the pinned `is-builtin-module` static list, mirrored below; the
// list contains the `node:` form so deprecated entries behave identically).
// Specifiers that already use the protocol, non-literal arguments, and
// third-party names stay silent. The finding is anchored on the string
// literal with the reference message "Prefer `node:fs` over `fs`." and no
// auto-fix is offered.
//
// SonarJS reports the rule with scope MAIN: test files (the pinned server's
// filename-based classification, shared with the analyzer's other rules)
// stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{Expression, Statement};
use oxc_ast_visit::{Visit, walk};
use oxc_span::Span;

/// The pinned `builtin-modules` list (both bare and `node:` forms), used
/// exactly like the reference rule: the specifier must be listed without
/// the prefix, and its `node:`-prefixed form must be listed as well.
const BUILTIN_MODULES: [&str; 109] = [
    "node:assert",
    "assert",
    "node:assert/strict",
    "assert/strict",
    "node:async_hooks",
    "async_hooks",
    "node:buffer",
    "buffer",
    "node:child_process",
    "child_process",
    "node:cluster",
    "cluster",
    "node:console",
    "console",
    "node:constants",
    "constants",
    "node:crypto",
    "crypto",
    "node:dgram",
    "dgram",
    "node:diagnostics_channel",
    "diagnostics_channel",
    "node:dns",
    "dns",
    "node:dns/promises",
    "dns/promises",
    "node:domain",
    "domain",
    "node:events",
    "events",
    "node:fs",
    "fs",
    "node:fs/promises",
    "fs/promises",
    "node:http",
    "http",
    "node:http2",
    "http2",
    "node:https",
    "https",
    "node:inspector",
    "inspector",
    "node:inspector/promises",
    "inspector/promises",
    "node:module",
    "module",
    "node:net",
    "net",
    "node:os",
    "os",
    "node:path",
    "path",
    "node:path/posix",
    "path/posix",
    "node:path/win32",
    "path/win32",
    "node:perf_hooks",
    "perf_hooks",
    "node:process",
    "process",
    "node:querystring",
    "querystring",
    "node:quic",
    "node:readline",
    "readline",
    "node:readline/promises",
    "readline/promises",
    "node:repl",
    "repl",
    "node:sea",
    "node:sqlite",
    "node:stream",
    "stream",
    "node:stream/consumers",
    "stream/consumers",
    "node:stream/promises",
    "stream/promises",
    "node:stream/web",
    "stream/web",
    "node:string_decoder",
    "string_decoder",
    "node:test",
    "node:test/reporters",
    "node:timers",
    "timers",
    "node:timers/promises",
    "timers/promises",
    "node:tls",
    "tls",
    "node:trace_events",
    "trace_events",
    "node:tty",
    "tty",
    "node:url",
    "url",
    "node:util",
    "util",
    "node:util/types",
    "util/types",
    "node:v8",
    "v8",
    "node:vm",
    "vm",
    "node:wasi",
    "wasi",
    "node:worker_threads",
    "worker_threads",
    "node:zlib",
    "zlib",
];

/// Entry point: `javascript:S7772` + `typescript:S7772` prefer-node-protocol
/// check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    if is_test_file(ctx.path) {
        // Scope MAIN: the pinned server classifies by filename.
        return Vec::new();
    }
    let mut collector = NodeProtocolCollector {
        sink: IssueSink {
            index: ctx.index,
            language: ctx.language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(ctx.program);
    collector.sink.issues
}

struct NodeProtocolCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for NodeProtocolCollector<'_> {
    fn visit_statement(&mut self, statement: &Statement<'a>) {
        match statement {
            Statement::ImportDeclaration(declaration) => {
                self.report_source(&declaration.source.value, declaration.source.span);
            }
            Statement::ExportFromDeclaration(declaration) => {
                self.report_source(&declaration.source.value, declaration.source.span);
            }
            _ => {}
        }
        walk::walk_statement(self, statement);
    }

    fn visit_expression(&mut self, expression: &Expression<'a>) {
        match expression {
            Expression::ImportExpression(import) => {
                if let Expression::StringLiteral(source) = &import.source {
                    self.report_source(&source.value, source.span);
                }
            }
            Expression::CallExpression(call) => {
                // Reference `isStaticRequire` / `isMethodCall` require a
                // non-optional call with exactly one literal argument.
                let is_static_require = !call.optional
                    && matches!(&call.callee, Expression::Identifier(id) if id.name == "require");
                let is_process_get_builtin_module = !call.optional
                    && matches!(
                        &call.callee,
                        Expression::StaticMemberExpression(member)
                            if !member.optional
                                && member.property.name == "getBuiltinModule"
                                && matches!(&member.object, Expression::Identifier(id) if id.name == "process")
                    );
                if (is_static_require || is_process_get_builtin_module)
                    && call.arguments.len() == 1
                    && let Some(Expression::StringLiteral(literal)) = call
                        .arguments
                        .first()
                        .and_then(|argument| argument.as_expression())
                {
                    self.report_source(&literal.value, literal.span);
                }
            }
            _ => {}
        }
        walk::walk_expression(self, expression);
    }

    fn visit_ts_import_type(&mut self, import: &oxc_ast::ast::TSImportType<'a>) {
        self.report_source(&import.source.value, import.source.span);
        walk::walk_ts_import_type(self, import);
    }
}

impl NodeProtocolCollector<'_> {
    fn report_source(&mut self, value: &str, literal: Span) {
        if value.starts_with("node:") || !BUILTIN_MODULES.contains(&value) {
            return;
        }
        let prefixed = format!("node:{value}");
        if !BUILTIN_MODULES.contains(&prefixed.as_str()) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S7772",
            &format!("Prefer `node:{value}` over `{value}`."),
            literal,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7772_flags_pinned_exceljs_require_sites() {
        // Pinned oracle: exceljs@5bed18b lib/csv/csv.js:1 `require('fs')` and
        // lib/csv/line-buffer.js:1 `require('events')` (29 reference findings).
        let source = "\
const fs = require('fs');
const path = require('path');
const {promisify} = require('util');
const other = require('lodash');
const prefixed = require('node:fs');
const dynamic = require(resolved);
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7772"), 3);
        let report = js(source);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7772")
            .expect("pinned exceljs require must be reported");
        assert_eq!(issue.message, "Prefer `node:fs` over `fs`.");
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("const fs = require(".len()).unwrap()
        );
    }

    #[test]
    fn s7772_flags_import_and_export_and_dynamic_forms() {
        let source = "\
import fs from 'fs';
import 'events';
export {default as fs} from 'path';
const dynamic = import('crypto');
export * from 'node:http';
import {other} from './local.js';
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7772"), 4);
    }

    #[test]
    fn s7772_flags_ts_import_type_and_process_get_builtin_module() {
        let source = "\
type Fs = import('fs');
const fs = process.getBuiltinModule('crypto');
type Other = import('node:fs');
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7772"), 2);
    }

    #[test]
    fn s7772_stays_silent_for_non_builtins_and_prefixed_forms() {
        let silent = "\
const lodash = require('lodash');
const scoped = require('@scope/pkg');
const local = require('./utils');
const prefixed = require('node:fs/promises');
const already = require('node:test');
";
        assert_eq!(count_key(&js_keys(silent), "javascript:S7772"), 0);
    }

    #[test]
    fn s7772_stays_silent_in_test_files_like_reference_main_scope() {
        // The pinned server classifies `*.spec.js` as TEST and reports the
        // MAIN-scoped rule only on MAIN files.
        let source = "const fs = require('fs');\n";
        let report = crate::analyze(
            PathBuf::from("spec/integration/workbook.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&report), "javascript:S7772"), 0);
        let main_report = crate::analyze(
            PathBuf::from("lib/csv/csv.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&main_report), "javascript:S7772"), 1);
    }
}
