// Rule module s2933_tb_readonly_candidate_fields (generated).
use crate::support::{IssueSink, RuleScope};
use hoonarqube_ir::{FlowLocation, IssueFlow};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S2933` (TypeScript only): private fields written only at their
/// declaration initializer or inside the constructor become readonly.
pub(crate) fn check_tb_readonly_candidate_fields(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = ReadonlyFieldCollector::default();
    collector.visit_program(program);
    for finding in collector.findings {
        let message = if finding.fields.len() == 1 {
            "Mark this member as `readonly`."
        } else {
            "Mark these members as `readonly`."
        };
        sink.emit_span(RuleScope::TsOnly, "S2933", message, finding.class_span);
        if RuleScope::TsOnly.active(sink.language)
            && let Some(issue) = sink.issues.last_mut()
        {
            issue.flows = finding
                .fields
                .into_iter()
                .map(|field| IssueFlow {
                    locations: vec![FlowLocation::in_primary_file(
                        format!(
                            "Member '{}' is never reassigned; mark it as `readonly`.",
                            field.name
                        ),
                        sink.index.range(field.span),
                    )],
                })
                .collect();
        }
    }
}

/// Private class fields written only at declaration or in the constructor
/// (`S2933`, TS only). The stack entry is `(name, declaration span, initialized)`.
pub(crate) struct ReadonlyFinding {
    pub(crate) class_span: Span,
    pub(crate) fields: Vec<ReadonlyField>,
}
pub(crate) struct ReadonlyField {
    pub(crate) name: String,
    pub(crate) span: Span,
}
#[derive(Default)]
pub(crate) struct ReadonlyFieldCollector<'p> {
    pub(crate) stack: Vec<Vec<(&'p str, Span, bool)>>,
    pub(crate) findings: Vec<ReadonlyFinding>,
    pub(crate) writes: Vec<(&'p str, Span, bool)>,
    pub(crate) constructor_depth: u32,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s2933_groups_members_at_class_with_exact_reference_locations() {
        let source = "export class Single {\n  private value: number;\n  constructor(value: number) { this.value = value; }\n  get() { return this.value; }\n}\nexport class Multiple {\n  private first = 1;\n  private second = 2;\n  get() { return this.first + this.second; }\n}\nexport class Mutable {\n  private value = 1;\n  advance() { this.value++; }\n  get() { return this.value; }\n}\nexport const Anonymous = class {\n  private value = 1;\n  get() { return this.value; }\n};\n";
        let report = ts(source);
        let issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.rule_key == "typescript:S2933")
            .collect();
        assert_eq!(issues.len(), 3);
        for (finding, (line, start, end, message, members)) in issues.iter().zip([
            (
                1,
                13,
                19,
                "Mark this member as `readonly`.",
                vec![(2, 15, "value")],
            ),
            (
                6,
                13,
                21,
                "Mark these members as `readonly`.",
                vec![(7, 15, "first"), (8, 16, "second")],
            ),
            (
                16,
                25,
                30,
                "Mark this member as `readonly`.",
                vec![(17, 15, "value")],
            ),
        ]) {
            assert_eq!(
                finding.range,
                hoonarqube_ir::Range {
                    start: pos(line, start),
                    end: pos(line, end)
                }
            );
            assert_eq!(finding.message, message);
            assert_eq!(finding.flows.len(), members.len());
            for (flow, (member_line, member_end, name)) in finding.flows.iter().zip(members) {
                assert_eq!(
                    flow.locations,
                    vec![hoonarqube_ir::FlowLocation::in_primary_file(
                        format!("Member '{name}' is never reassigned; mark it as `readonly`."),
                        hoonarqube_ir::Range {
                            start: pos(member_line, 2),
                            end: pos(member_line, member_end)
                        },
                    )]
                );
            }
        }
    }

    #[test]
    fn constructor_only_fields_suggested_readonly_in_typescript() {
        let source =
            "class C {\n  private name;\n  constructor(value) {\n    this.name = value;\n  }\n}\n";
        assert_eq!(filtered(&ts(source), "S2933").len(), 1);
        assert_eq!(filtered(&js(source), "S2933").len(), 0);
        let method_written =
            "class C {\n  private count;\n  tick() {\n    this.count = 1;\n  }\n}\n";
        assert_eq!(filtered(&ts(method_written), "S2933").len(), 0);
        let already_readonly =
            "class C {\n  private readonly id;\n  constructor() {\n    this.id = 1;\n  }\n}\n";
        assert_eq!(filtered(&ts(already_readonly), "S2933").len(), 0);
        let initialized =
            "class C {\n  private preset = 1;\n  constructor() {\n    this.preset = 2;\n  }\n}\n";
        assert_eq!(filtered(&ts(initialized), "S2933").len(), 1);
    }

    #[test]
    fn declaration_initialized_private_fields_flagged() {
        // #477: `prefer-readonly` also covers fields initialized at the
        // declaration and never reassigned.
        let source = "class C {\n  private cache = new Map();\n  get(k) {\n    return this.cache.get(k);\n  }\n}\n";
        assert_eq!(filtered(&ts(source), "S2933").len(), 1);
        let hash_private =
            "class C {\n  #state = 0;\n  read() {\n    return this.#state;\n  }\n}\n";
        assert_eq!(filtered(&ts(hash_private), "S2933").len(), 1);
    }

    #[test]
    fn non_private_fields_stay_silent() {
        // #478: `prefer-readonly` never considers public or protected
        // fields, whatever their assignment pattern.
        let source = "class C {\n  parent;\n  view;\n  protected index;\n  constructor(v, i, p) {\n    this.view = v;\n    this.index = i;\n    this.parent = p;\n  }\n}\n";
        assert_eq!(filtered(&ts(source), "S2933").len(), 0);
        let never_written = "class C {\n  private untouched;\n}\n";
        assert_eq!(filtered(&ts(never_written), "S2933").len(), 0);
    }
}
