use crate::context::FlowState;
use crate::engine::scope::RaiseContext;
use crate::support::scan_flow_statements;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_raise_and_jump_flow(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    scan_flow_statements(
        parsed.syntax().body.as_slice(),
        FlowState {
            context: RaiseContext::Outside,
            finally_depth: 0,
            loop_depth: 0,
        },
        &mut issues,
        index,
        source,
    );
    issues
}
