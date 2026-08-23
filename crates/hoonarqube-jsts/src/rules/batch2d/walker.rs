// Family walker for 'batch2d' (generated).
use super::s3512_es_idioms::check_es_idioms;
use crate::context::AnalysisContext;
use crate::engine::scope_model::collect_array_binding_names;
use crate::support::{IssueSink, LineIndex};
use crate::{
    ClassAccessorCollector, DuplicationCollector, FunctionMetricsCollector, JstsLanguage,
    KeywordPlacementCollector, PromiseFlowCollector,
};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;

/// All Batch2d checks in one place: the control-flow remainder groups D/E
/// (`S3776`, `S3796`, `S3801`, `S3854`, `S3972`, `S3973`, `S4275`,
/// `S4619`, `S4634`, `S4822`, `S6635`, `S6671`, `S6861`, `S1067`,
/// `S1534`, `S1536`, `S1541`) and the ES2015+ idiom section (`S3358`,
/// `S3498`, `S3499`, `S3512`, `S3513`, `S3514`, `S3523`, `S4158`,
/// `S6582`, `S6594`).
pub(crate) fn check_batch2d_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = check_function_metrics(program, index, language);
    issues.extend(check_class_accessors(program, index, language));
    issues.extend(check_keyword_placement(program, source, index, language));
    issues.extend(check_promise_flows(program, index, language));
    issues.extend(check_duplications(program, index, language));
    issues.extend(check_es_idioms(program, index, language));
    issues
}

pub(crate) fn check_function_metrics(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = FunctionMetricsCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

pub(crate) fn check_class_accessors(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ClassAccessorCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

pub(crate) fn check_keyword_placement(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = KeywordPlacementCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        index,
    };
    collector.visit_program(program);
    collector.sink.issues
}

pub(crate) fn check_promise_flows(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = PromiseFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        array_bindings: collect_array_binding_names(program),
    };
    collector.visit_program(program);
    collector.sink.issues
}

pub(crate) fn check_duplications(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = DuplicationCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_batch2d_rules(ctx.program, ctx.source, ctx.index, ctx.language)
}
