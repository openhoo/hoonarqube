use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    callee_name, expression_name, invocation_arguments, invocation_receiver,
    resolved_identifier_type,
};
use crate::rules::literals::{is_string_literal, literal_inner_text};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4036 — launching a bare command name resolves through
/// `PATH`, so which binary runs depends on the caller's environment.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| is_process_start(*call, source))
        .filter(|call| {
            process_start_target(*call, source)
                .is_some_and(|target| is_path_resolved_literal(target, source))
        })
        .map(|call| {
            issue(
                language,
                "S4036",
                "Make sure the \"PATH\" used to find this command includes only what you intend.",
                range_of(call, source),
            )
        })
        .collect()
}

/// Matches only framework type spellings identifiable without semantic
/// information. `service.Process.Start(...)` must not be mistaken for the BCL
/// API merely because its receiver ends in `Process`.
fn is_process_start(call: Node<'_>, source: &str) -> bool {
    if callee_name(call, source) != Some("Start") {
        return false;
    }
    invocation_receiver(call).is_some_and(|receiver| match node_text(receiver, source) {
        "Process" => {
            resolved_identifier_type(receiver, source).is_none_or(|ty| simple_name(ty) == "Process")
        }
        "System.Diagnostics.Process" | "global::System.Diagnostics.Process" => true,
        _ => false,
    })
}

/// Resolves the executable-bearing argument of known `Process.Start`
/// overloads. A string first argument is always `fileName`, independent of
/// remaining overload arguments. Named arguments may appear out of order.
fn process_start_target<'t>(call: Node<'t>, source: &str) -> Option<Node<'t>> {
    let arguments = invocation_arguments(call);
    let explicit = named_argument(&arguments, "fileName", source)
        .or_else(|| named_argument(&arguments, "startInfo", source));
    let target = explicit.or_else(|| {
        let first = arguments.first()?;
        first
            .child_by_field_name("name")
            .is_none()
            .then(|| argument_value(*first))
            .flatten()
    })?;

    process_start_info_file_name(target, source).or(Some(target))
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
    if creation.kind() != "object_creation_expression"
        || creation
            .child_by_field_name("type")
            .is_none_or(|ty| simple_name(node_text(ty, source)) != "ProcessStartInfo")
    {
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
}
