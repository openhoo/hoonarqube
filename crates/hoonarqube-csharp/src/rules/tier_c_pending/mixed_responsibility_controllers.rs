use super::support::member_declared_type;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6960 — controllers mixing many actions with many injected
/// services. Subset: classes named `…Controller` declaring at least five
/// public methods and three distinct interface-typed `readonly` fields;
/// responsibility quality itself stays out of scope.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class| !is_error_tainted(*class))
        .filter(|class| {
            class
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source).ends_with("Controller"))
        })
        .filter(|class| {
            let actions = member_declarations_of_kind(*class, "method_declaration")
                .into_iter()
                .filter(|method| has_modifier(&modifiers_of(*method, source), "public"))
                .count();
            let services = injected_interface_field_types(*class, source).len();
            actions >= MIXED_CONTROLLER_ACTION_THRESHOLD
                && services >= MIXED_CONTROLLER_SERVICE_THRESHOLD
        })
        .filter_map(|class| class.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S6960",
                "Split this controller; it mixes many actions with several injected services.",
                range_of(name, source),
            )
        })
        .collect()
}

/// Action and service-diversity thresholds of the S6960 heuristic.
const MIXED_CONTROLLER_ACTION_THRESHOLD: usize = 5;

const MIXED_CONTROLLER_SERVICE_THRESHOLD: usize = 3;

/// Distinct interface-typed `readonly` fields of a type (the constructor
/// injection shape).
fn injected_interface_field_types<'a>(
    type_node: Node<'_>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
    type_members(type_node)
        .into_iter()
        .filter(|member| {
            member.kind() == "field_declaration"
                && has_modifier(&modifiers_of(*member, source), "readonly")
        })
        .filter_map(member_declared_type)
        .map(|type_node| simple_name(node_text(type_node, source)))
        .filter(|declared| {
            declared.len() > 1
                && declared.starts_with('I')
                && declared
                    .chars()
                    .nth(1)
                    .is_some_and(|c| c.is_ascii_uppercase())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6960_below_either_threshold_stays_clean() {
        let report = analyze_default(
            "class DashboardController\n{\n    private readonly IUserService users;\n    private readonly IAuditService audit;\n    public void List() { }\n    public void Show() { }\n    public void Create() { }\n    public void Edit() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6960").is_empty());
    }

    #[test]
    fn s6960_service_fields_must_be_readonly_and_interface_typed() {
        let report = analyze_default(
            "class DashboardController\n{\n    private UserService users;\n    private AuditService audit;\n    private ReportService reports;\n    public void List() { }\n    public void Show() { }\n    public void Create() { }\n    public void Edit() { }\n    public void Remove() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6960").is_empty());
    }

    #[test]
    fn s6960_duplicate_service_types_count_once() {
        let report = analyze_default(
            "class DashboardController\n{\n    private readonly IUserService first;\n    private readonly IUserService second;\n    private readonly IAuditService audit;\n    public void List() { }\n    public void Show() { }\n    public void Create() { }\n    public void Edit() { }\n    public void Remove() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6960").is_empty());
    }

    #[test]
    fn s6960_non_controller_names_are_out_of_scope() {
        let report = analyze_default(
            "class DashboardHandler\n{\n    private readonly IUserService users;\n    private readonly IAuditService audit;\n    private readonly IReportService reports;\n    public void List() { }\n    public void Show() { }\n    public void Create() { }\n    public void Edit() { }\n    public void Remove() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6960").is_empty());
    }

    #[test]
    fn s6960_flags_each_violating_controller_at_its_own_line() {
        let report = analyze_default(
            "class AlphaController\n{\n    private readonly IUserService users;\n    private readonly IAuditService audit;\n    private readonly IReportService reports;\n    public void List() { }\n    public void Show() { }\n    public void Create() { }\n    public void Edit() { }\n    public void Remove() { }\n}\nclass BetaController\n{\n    private readonly IUserService users;\n    private readonly IAuditService audit;\n    private readonly IReportService reports;\n    public void List() { }\n    public void Show() { }\n    public void Create() { }\n    public void Edit() { }\n    public void Remove() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6960");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 12);
    }
}
