// Rule module s3512_es_idioms (generated).
use crate::JstsLanguage;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;
use oxc_span::Span;

pub(crate) fn check_es_idioms(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = EsIdiomCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        concat_roots: Vec::new(),
        arguments_shadowed: Vec::new(),
        s6582_spans: Vec::new(),
    };
    collector.visit_program(program);
    let roots: Vec<Span> = collector
        .concat_roots
        .iter()
        .copied()
        .filter(|span| {
            // Left-nested chains share their start offset with the root,
            // so containment is checked inclusively on both edges.
            !collector.concat_roots.iter().any(|other| {
                (other.start, other.end) != (span.start, span.end)
                    && other.start <= span.start
                    && span.end <= other.end
            })
        })
        .collect();
    for span in roots {
        collector.sink.emit_span(
            RuleScope::Both,
            "S3512",
            "Replace this string concatenation with a template literal.",
            span,
        );
    }
    collector.sink.issues
}

/// `S3358`, `S3498`, `S3499`, `S3512`, `S3513`, `S3514`, `S3523`,
/// `S4158`, `S6582`, and `S6594` in one traversal.
pub(crate) struct EsIdiomCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Pure string-concatenation subroots; minimal spans resolved after the
    /// traversal (`S3512`).
    pub(crate) concat_roots: Vec<Span>,
    /// One frame per enclosing function unit recording whether it shadows
    /// the name `arguments` (`S3513`).
    pub(crate) arguments_shadowed: Vec<bool>,
    /// Spans of already-emitted `S6582` chain reports; nested operands are
    /// visited again by the traversal and must stay silent.
    pub(crate) s6582_spans: Vec<Span>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn pure_string_concatenation_suggests_template_literals() {
        let flagged = js_keys("const s = 'a' + 'b' + 'c';\n");
        // Only the outermost chain root is flagged.
        assert_eq!(count_key(&flagged, "javascript:S3512"), 1);

        let dynamic = js_keys("const t = 'a' + name;\n");
        assert_eq!(count_key(&dynamic, "javascript:S3512"), 0);
    }
}
