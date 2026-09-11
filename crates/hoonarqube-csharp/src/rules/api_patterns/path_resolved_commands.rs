use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    callee_name, enclosing_callable, expression_name, invocation_arguments, invocation_receiver,
    operator_of, resolved_identifier_type,
};
use crate::rules::literals::{declarator_initializer, is_string_literal, literal_inner_text};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4036 — launching a bare command name resolves through
/// `PATH`, so which binary runs depends on the caller's environment.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| is_process_start(root, *call, source))
        .filter(|call| {
            process_start_target(*call, source)
                .is_some_and(|target| is_path_resolved_literal(target, source))
        })
        .map(|call| {
            issue(
                language,
                "S4036",
                "Use an absolute path for this command.",
                range_of(process_start_issue_anchor(call, source), source),
            )
        })
        .collect()
}

/// Matches only framework type spellings identifiable without semantic
/// information. `service.Process.Start(...)` must not be mistaken for the BCL
/// API merely because its receiver ends in `Process`.
fn is_process_start(root: Node<'_>, call: Node<'_>, source: &str) -> bool {
    if callee_name(call, source) != Some("Start") {
        return false;
    }
    invocation_receiver(call).is_some_and(|receiver| match node_text(receiver, source) {
        "Process" => {
            !has_local_type(root, "Process", source)
                && resolved_identifier_type(receiver, source)
                    .is_none_or(|ty| simple_name(ty) == "Process")
        }
        "System.Diagnostics.Process" | "global::System.Diagnostics.Process" => true,
        _ => false,
    })
}

fn has_local_type(root: Node<'_>, wanted: &str, source: &str) -> bool {
    collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
            "interface_declaration",
            "enum_declaration",
        ],
    )
    .into_iter()
    .filter_map(|declaration| declaration.child_by_field_name("name"))
    .any(|name| simple_name(node_text(name, source)) == wanted)
}

/// Resolves the executable-bearing argument of known `Process.Start`
/// overloads. A string first argument is always `fileName`, independent of
/// remaining overload arguments; inline or same-callable local
/// `ProcessStartInfo` initializers are resolved, while helper aliases stay
/// unresolved.
fn process_start_target<'t>(call: Node<'t>, source: &str) -> Option<Node<'t>> {
    let target = process_start_argument(call, source)?;
    process_start_info_file_name(target, source)
        .or_else(|| bound_process_start_info_file_name(target, call, source))
        .or(Some(target))
}

fn process_start_argument<'t>(call: Node<'t>, source: &str) -> Option<Node<'t>> {
    let arguments = invocation_arguments(call);
    let explicit = named_argument(&arguments, "fileName", source)
        .or_else(|| named_argument(&arguments, "startInfo", source));
    explicit.or_else(|| {
        let first = arguments.first()?;
        first
            .child_by_field_name("name")
            .is_none()
            .then(|| argument_value(*first))
            .flatten()
    })
}

fn named_argument<'t>(arguments: &[Node<'t>], wanted: &str, source: &str) -> Option<Node<'t>> {
    arguments.iter().find_map(|argument| {
        argument
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == wanted)
            .then(|| argument_value(*argument))
            .flatten()
    })
}

/// Value expression is final named child because optional named-argument
/// identifier precedes it in C# CST.
fn argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = argument.walk();
    argument.named_children(&mut cursor).last()
}

/// Extracts `FileName` from inline `ProcessStartInfo` creation. An object
/// initializer wins over constructor value because it is applied later.
fn process_start_info_file_name<'t>(creation: Node<'t>, source: &str) -> Option<Node<'t>> {
    if !is_process_start_info_creation(creation, source) {
        return None;
    }

    if let Some(initializer) = creation.child_by_field_name("initializer") {
        let mut cursor = initializer.walk();
        if let Some(value) = initializer.named_children(&mut cursor).find_map(|member| {
            (member.kind() == "assignment_expression")
                .then(|| {
                    let left = member.child_by_field_name("left")?;
                    (expression_name(left, source) == Some("FileName"))
                        .then(|| member.child_by_field_name("right"))
                        .flatten()
                })
                .flatten()
        }) {
            return Some(value);
        }
    }

    let arguments = creation
        .child_by_field_name("arguments")
        .map(direct_arguments)
        .unwrap_or_default();
    named_argument(&arguments, "fileName", source).or_else(|| {
        let first = arguments.first()?;
        first
            .child_by_field_name("name")
            .is_none()
            .then(|| argument_value(*first))
            .flatten()
    })
}

fn is_process_start_info_creation(creation: Node<'_>, source: &str) -> bool {
    creation.kind() == "object_creation_expression"
        && creation
            .child_by_field_name("type")
            .is_some_and(|ty| is_process_start_info_type(node_text(ty, source)))
}

fn is_process_start_info_type(type_text: &str) -> bool {
    matches!(
        type_text.trim(),
        "ProcessStartInfo"
            | "System.Diagnostics.ProcessStartInfo"
            | "global::System.Diagnostics.ProcessStartInfo"
    )
}

fn bound_process_start_info_creation<'t>(
    target: Node<'t>,
    call: Node<'t>,
    source: &str,
) -> Option<Node<'t>> {
    if target.kind() != "identifier" {
        return None;
    }
    let owner = enclosing_callable(call)?;
    let wanted = node_text(target, source);
    collect_kinds(owner, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.start_byte() < target.start_byte())
        .filter(|declarator| {
            enclosing_callable(*declarator).is_some_and(|actual| actual.id() == owner.id())
        })
        .filter(|declarator| {
            declarator
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == wanted)
        })
        .max_by_key(Node::start_byte)
        .and_then(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let initializer = declarator_initializer(declarator, name)?;
            is_process_start_info_creation(initializer, source).then_some(initializer)
        })
}

fn bound_process_start_info_file_name<'t>(
    target: Node<'t>,
    call: Node<'t>,
    source: &str,
) -> Option<Node<'t>> {
    let creation = bound_process_start_info_creation(target, call, source)?;
    if let Some(assignment) = bound_process_start_info_assignment(target, call, source) {
        return assignment.child_by_field_name("right");
    }
    process_start_info_file_name(creation, source)
}

fn bound_process_start_info_assignment<'t>(
    target: Node<'t>,
    call: Node<'t>,
    source: &str,
) -> Option<Node<'t>> {
    if target.kind() != "identifier" {
        return None;
    }
    let owner = enclosing_callable(call)?;
    let wanted = node_text(target, source);
    collect_kinds(owner, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| assignment.start_byte() < call.start_byte())
        .filter(|assignment| {
            enclosing_callable(*assignment).is_some_and(|actual| actual.id() == owner.id())
        })
        .filter(|assignment| operator_of(*assignment) == Some("="))
        .filter(|assignment| {
            let Some(left) = assignment.child_by_field_name("left") else {
                return false;
            };
            left.kind() == "member_access_expression"
                && expression_name(left, source) == Some("FileName")
                && left
                    .child_by_field_name("expression")
                    .is_some_and(|base| simple_name(node_text(base, source)) == wanted)
        })
        .max_by_key(Node::start_byte)
}

fn process_start_info_file_name_anchor<'t>(creation: Node<'t>, source: &str) -> Option<Node<'t>> {
    if !is_process_start_info_creation(creation, source) {
        return None;
    }
    let initializer = creation.child_by_field_name("initializer")?;
    let mut cursor = initializer.walk();
    initializer.named_children(&mut cursor).find_map(|member| {
        (member.kind() == "assignment_expression").then(|| {
            let left = member.child_by_field_name("left")?;
            (expression_name(left, source) == Some("FileName")).then_some(left)
        })?
    })
}

fn process_start_issue_anchor<'t>(call: Node<'t>, source: &str) -> Node<'t> {
    let Some(target) = process_start_argument(call, source) else {
        return call;
    };
    process_start_info_file_name_anchor(target, source)
        .or_else(|| {
            bound_process_start_info_assignment(target, call, source)
                .and_then(|assignment| assignment.child_by_field_name("left"))
        })
        .or_else(|| {
            bound_process_start_info_creation(target, call, source)
                .and_then(|creation| process_start_info_file_name_anchor(creation, source))
        })
        .unwrap_or(target)
}

fn direct_arguments(arguments: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "argument")
        .collect()
}

fn is_path_resolved_literal(literal: Node<'_>, source: &str) -> bool {
    if !is_string_literal(literal) {
        return false;
    }
    let command = literal_inner_text(literal, source);
    !command.is_empty() && !command.contains(['/', '\\'])
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn flags_string_overloads_literal_forms_and_dot_prefixed_names() {
        let report = analyze_default(
            r#"
class C {
    void M() {
        Process.Start("tool", "--version");
        Process.Start(arguments: "--version", fileName: @"tool");
        Process.Start("""tool""");
        Process.Start(".tool");
        System.Diagnostics.Process.Start("qualified");
        global::System.Diagnostics.Process.Start("global-qualified");
    }
}
"#,
        );

        assert_eq!(with_key(&report, "csharpsquid:S4036").len(), 6);
    }

    #[test]
    fn flags_inline_process_start_info_file_names() {
        let report = analyze_default(
            r#"
class C {
    void M() {
        Process.Start(new ProcessStartInfo("first"));
        Process.Start(new ProcessStartInfo(fileName: @"second"));
        Process.Start(new ProcessStartInfo { FileName = """third""" });
        Process.Start(startInfo: new System.Diagnostics.ProcessStartInfo("fourth"));
    }
}
"#,
        );

        assert_eq!(with_key(&report, "csharpsquid:S4036").len(), 4);
    }

    #[test]
    fn ignores_non_path_lookups_empty_names_and_unrelated_receivers() {
        let report = analyze_default(
            r#"
class C {
    void M(dynamic service, dynamic runner) {
        Runner Process = GetRunner();
        Process.Start("");
        Process.Start(@"");
        Process.Start("""""");
        Process.Start("./tool");
        Process.Start(@"tools\tool.exe", "--version");
        Process.Start(new ProcessStartInfo("/usr/bin/tool"));
        Process.Start(new ProcessStartInfo("fallback") { FileName = "/usr/bin/tool" });
        Process.Start("task");
        service.Process.Start("tool");
        runner.Start("tool");
    }
}
"#,
        );

        assert!(with_key(&report, "csharpsquid:S4036").is_empty());
    }
    #[test]
    fn flags_bare_executable_in_a_local_process_start_info() {
        let report = analyze_default(
            "using System.Diagnostics;\n\npublic static class ProcessLauncher\n{\n    public static Process? Run()\n    {\n        var start = new ProcessStartInfo\n        {\n            FileName = \"binary\",\n            UseShellExecute = false,\n        };\n        return Process.Start(start);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4036");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].message, "Use an absolute path for this command.");
        assert_eq!(flagged[0].range.start.line, 9);
        assert_eq!(flagged[0].range.start.column, 12);
        assert_eq!(flagged[0].range.end.line, 9);
        assert_eq!(flagged[0].range.end.column, 20);
    }

    #[test]
    fn later_process_start_info_file_name_assignments_are_resolved() {
        let report = analyze_default(
            r#"
using System.Diagnostics;

class C {
    void Safe() {
        var start = new ProcessStartInfo("binary");
        start.FileName = "/usr/bin/binary";
        Process.Start(start);
    }

    void Unsafe() {
        var start = new ProcessStartInfo("/usr/bin/binary");
        start.FileName = "binary";
        Process.Start(start);
    }
}
"#,
        );
        let flagged = with_key(&report, "csharpsquid:S4036");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].message, "Use an absolute path for this command.");
    }
    #[test]
    fn keeps_absolute_local_process_start_info_and_safe_aliases_clean() {
        let report = analyze_default(
            "using System.Diagnostics;\n\npublic static class ProcessLauncher\n{\n    public static Process? Run()\n    {\n        var start = new ProcessStartInfo\n        {\n            FileName = \"/usr/bin/binary\",\n            UseShellExecute = false,\n        };\n        return Process.Start(start);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4036").is_empty());

        let alias = analyze_default(
            "using System.Diagnostics;\n\npublic static class ProcessLauncherAlias\n{\n    public static Process? Run() => Process.Start(CreateStartInfo());\n\n    private static ProcessStartInfo CreateStartInfo()\n        => new() { FileName = \"/usr/bin/binary\", UseShellExecute = false };\n}\n",
        );
        assert!(with_key(&alias, "csharpsquid:S4036").is_empty());
    }
}
