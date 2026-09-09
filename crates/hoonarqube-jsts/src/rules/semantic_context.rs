//! Semantic JS/TS rules fed exclusively by [`ProjectSemanticContext`] facts.
//!
//! This module intentionally contains no text/name heuristics for types or
//! symbols.  The TypeScript helper has already resolved aliases, declaration
//! ownership, module resolution, control-flow types, and compiler options.

use crate::JstsLanguage;
use crate::project_context::{SemanticFileFacts, SemanticSpan};
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_span::Span;

const S1874_MESSAGE: &str = "This API is deprecated.";
const S6627_MESSAGE: &str = "Do not use internal APIs of your dependencies";
const S4328_MESSAGE: &str = "Either remove this import or add it as a dependency.";
const S4325_MESSAGE: &str =
    "This assertion is unnecessary since it does not change the type of the expression.";
const S6606_TERNARY_MESSAGE: &str = "Prefer using nullish coalescing operator (`??`) instead of a ternary expression, as it is simpler to read.";
const S6606_MESSAGE: &str = "Prefer using nullish coalescing operator (`??`) instead of a logical or (`||`), as it is a safer operator.";
const S1125_MESSAGE: &str = "Refactor the code to avoid using this boolean literal.";
const S4623_MESSAGE: &str = "Remove this redundant \"undefined\".";
const S4043_MESSAGE: &str =
    "Move this array operation to a separate statement or replace it with a non-mutating method.";
const S4782_MESSAGE: &str =
    "Consider removing 'undefined' type or '?' specifier, one of them is redundant.";
const S6439_MESSAGE: &str = "Convert the conditional to a boolean to avoid leaked value.";
pub(crate) fn run(
    file: &SemanticFileFacts,
    source: &str,
    language: JstsLanguage,
    whitelist: &[String],
) -> Vec<Issue> {
    let index = LineIndex::new(source);
    let mut sink = IssueSink {
        index: &index,
        language,
        issues: Vec::new(),
    };

    emit_deprecated(&mut sink, file, source);
    emit_imports(&mut sink, file, source, language, whitelist);
    if language == JstsLanguage::TypeScript {
        emit_typescript_facts(&mut sink, file, source);
    }
    sink.issues
}

fn emit_deprecated(sink: &mut IssueSink<'_>, file: &SemanticFileFacts, source: &str) {
    for deprecated in &file.facts.deprecated {
        let message = if deprecated.message.trim().is_empty() {
            S1874_MESSAGE
        } else {
            &deprecated.message
        };
        emit_span(
            sink,
            RuleScope::Both,
            "S1874",
            message,
            source,
            &deprecated.span,
        );
    }
}

fn emit_imports(
    sink: &mut IssueSink<'_>,
    file: &SemanticFileFacts,
    source: &str,
    language: JstsLanguage,
    whitelist: &[String],
) {
    for import in &file.imports {
        // S6627's pinned visitor handles only import declarations and
        // require calls. Reexports remain resolved facts but are not
        // diagnostic sites for this rule.
        let rule_import = matches!(import.kind.as_str(), "import" | "require");
        if rule_import
            && import.internal
            && matches!(import.internal_reason.as_deref(), Some("module-path"))
            && (import.resolved || import.module.contains("node_modules"))
        {
            emit_span(
                sink,
                RuleScope::Both,
                "S6627",
                S6627_MESSAGE,
                source,
                &import.span,
            );
        }

        // S4328 reports the exact import keyword/require callee proven by the
        // helper. Ineligible forms and old/incomplete facts do not fall back
        // to the owning declaration range.
        if language == JstsLanguage::TypeScript
            && rule_import
            && import.external
            && !import.dependency_exempt
            && !import.declared_dependency
            && !is_whitelisted(&import.package, whitelist)
            && import.unresolved_reason.as_deref() != Some("missing-user-module")
            && (!import.resolved || import.external_library)
            && let Some(diagnostic_span) = import.diagnostic_span.as_ref()
        {
            emit_span(
                sink,
                RuleScope::TsOnly,
                "S4328",
                S4328_MESSAGE,
                source,
                diagnostic_span,
            );
        }
    }
}

fn emit_typescript_facts(sink: &mut IssueSink<'_>, file: &SemanticFileFacts, source: &str) {
    for assertion in &file.facts.assertions {
        if assertion.unnecessary && !assertion.generic_call {
            emit_span(
                sink,
                RuleScope::TsOnly,
                "S4325",
                S4325_MESSAGE,
                source,
                &assertion.span,
            );
        }
    }
    for nullish in &file.facts.nullish {
        if nullish.report && nullish.kind != "logical-or-assignment" {
            let message = if nullish.kind == "conditional" {
                S6606_TERNARY_MESSAGE
            } else {
                S6606_MESSAGE
            };
            emit_span(
                sink,
                RuleScope::TsOnly,
                "S6606",
                message,
                source,
                &nullish.span,
            );
        }
    }
}

/// Emits findings whose existence is established by a compiler quick-fix fact
/// even when the syntax-only Oxc pass did not create the corresponding issue.
pub(crate) fn run_checker_fallbacks(
    file: &SemanticFileFacts,
    source: &str,
    language: JstsLanguage,
) -> Vec<Issue> {
    let index = LineIndex::new(source);
    let mut sink = IssueSink {
        index: &index,
        language,
        issues: Vec::new(),
    };
    for quickfix in &file.facts.quickfixes {
        if quickfix.actions.is_empty() {
            continue;
        }
        let rule = quickfix
            .rule_key
            .rsplit(':')
            .next()
            .unwrap_or(&quickfix.rule_key);
        match rule {
            "S1125" => emit_span(
                &mut sink,
                RuleScope::Both,
                "S1125",
                S1125_MESSAGE,
                source,
                &quickfix.subject_span,
            ),
            "S4043" => emit_span(
                &mut sink,
                RuleScope::Both,
                "S4043",
                S4043_MESSAGE,
                source,
                &quickfix.subject_span,
            ),
            "S4782" if language == JstsLanguage::TypeScript => {
                emit_span(
                    &mut sink,
                    RuleScope::TsOnly,
                    "S4782",
                    S4782_MESSAGE,
                    source,
                    &quickfix.subject_span,
                );
            }
            "S6439" => emit_span(
                &mut sink,
                RuleScope::Both,
                "S6439",
                S6439_MESSAGE,
                source,
                &quickfix.subject_span,
            ),
            "S4623" if language == JstsLanguage::TypeScript => {
                emit_span(
                    &mut sink,
                    RuleScope::TsOnly,
                    "S4623",
                    S4623_MESSAGE,
                    source,
                    &quickfix.subject_span,
                );
            }
            _ => {}
        }
    }
    sink.issues
}

fn emit_span(
    sink: &mut IssueSink<'_>,
    scope: RuleScope,
    rule: &str,
    message: &str,
    source: &str,
    span: &SemanticSpan,
) {
    let Some(span) = checked_span(source, span) else {
        return;
    };
    sink.emit_span(scope, rule, message, span);
}

fn checked_span(source: &str, span: &SemanticSpan) -> Option<Span> {
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    (start <= end
        && end <= source.len()
        && source.is_char_boundary(start)
        && source.is_char_boundary(end))
    .then(|| Span::new(span.start, span.end))
}

fn is_whitelisted(package: &str, whitelist: &[String]) -> bool {
    whitelist.iter().any(|item| {
        item == package
            || item.strip_suffix("/*").is_some_and(|prefix| {
                package == prefix || package.starts_with(&format!("{prefix}/"))
            })
            || (item.starts_with('@')
                && package.starts_with(item)
                && package.as_bytes().get(item.len()) == Some(&b'/'))
    })
}
