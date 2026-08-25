// Family walker for 'statement_sequences' (generated).
use super::s1488_scan_statement_sequence::scan_statement_sequence;
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{BlockStatement, FunctionBody};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_block_statement, walk_function_body, walk_program};

fn check_statement_sequences(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = StatementSequenceCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1488` and `S1763` over program bodies, block bodies, and function
/// bodies.
struct StatementSequenceCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for StatementSequenceCollector<'_> {
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        scan_statement_sequence(&mut self.sink, &it.body);
        walk_program(self, it);
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        scan_statement_sequence(&mut self.sink, &it.body);
        walk_block_statement(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        scan_statement_sequence(&mut self.sink, &it.statements);
        walk_function_body(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_statement_sequences(ctx.program, ctx.index, ctx.language)
}
