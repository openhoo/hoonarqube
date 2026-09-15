// Rule module s3512_es_idioms (generated).
use crate::JstsLanguage;
use crate::support::{IssueSink, LineIndex};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;
use oxc_span::Span;

pub(crate) fn check_es_idioms(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = EsIdiomCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        arguments_shadowed: Vec::new(),
        s6582_spans: Vec::new(),
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S3358`, `S3498`, `S3499`, `S3513`, `S3514`, `S3523`, `S4158`,
/// `S6582`, and `S6594` in one traversal. `S3512` moved to the
/// semantic-model module `s3512_template_literal` (issue #387).
pub(crate) struct EsIdiomCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// File source, used to compare computed member keys by text (`S6582`).
    pub(crate) source: &'index str,
    /// One frame per enclosing function unit recording whether it shadows
    /// the name `arguments` (`S3513`).
    pub(crate) arguments_shadowed: Vec<bool>,
    /// Spans of already-emitted `S6582` chain reports; nested operands are
    /// visited again by the traversal and must stay silent.
    pub(crate) s6582_spans: Vec<Span>,
}
