//! Preprocessor-directive parser recovery (#328).
//!
//! Tree-sitter cannot place a preprocessor directive inside an expression,
//! so an `#if` interleaved between the tokens of a call's argument list (the
//! minimized Dapper `SqlMapper.cs` static-constructor shape) produced an
//! ERROR tree and the analyzer refused the whole file.  The analyzer now
//! retries over deterministic byte-length-preserving views — directive
//! lines blanked, then conditional branches evaluated under the
//! undefined-symbol default — and analyzes the first clean view, while
//! input without directive recovery keeps failing closed.

use super::*;

/// Minimized from Dapper's `SqlMapper.cs` static constructor (#328): the
/// `#if` between the capacity argument `41` and `+ 4` sits inside the
/// argument list's expression, which the grammar alone cannot represent.
const DIRECTIVE_INSIDE_ARGUMENT_EXPRESSION: &str = "\
namespace Dapper
{
    public static partial class SqlMapper
    {
        static SqlMapper()
        {
            typeMap = new Dictionary<Type, TypeMapEntry>(41
#if NET6_0_OR_GREATER
                + 4 // {Date|Time}Only[?]
#endif
                )
            {
                [typeof(byte)] = DbType.Byte,
            };
        }

        static void Sample(bool condition)
        {
            if (condition) ;
        }
    }
}
";

#[test]
fn directive_inside_argument_expression_is_recovered_and_analyzed() {
    let tree = crate::parse(DIRECTIVE_INSIDE_ARGUMENT_EXPRESSION);
    assert!(
        !tree.root_node().has_error(),
        "directive lines interleaved in an argument list must recover to a clean parse: {}",
        tree.root_node().to_sexp()
    );
    let report = analyze_default(DIRECTIVE_INSIDE_ARGUMENT_EXPRESSION);
    let empty_statements = with_key(&report, "csharpsquid:S1116");
    assert_eq!(
        empty_statements.len(),
        1,
        "findings must be emitted from the recovered tree"
    );
    assert_eq!(empty_statements[0].range.start.line, 19);
    assert_eq!(report.metrics.lines, 22);
}

#[test]
fn recovery_views_preserve_byte_offsets_and_newline_styles() {
    let source = "class C {\r\n  void M() { Foo(1,\r\n#if DEBUG\r\n    2\r\n#endregion Area\r\n#endif\r\n  ); }\r\n}\r\n";
    let views = crate::preprocessor_recovery_views(source);
    assert!(!views.is_empty());
    for view in &views {
        assert_eq!(view.len(), source.len());
        assert!(!view.contains('#'));
        for (index, (original, recovered)) in source.bytes().zip(view.bytes()).enumerate() {
            assert!(
                original == recovered || recovered == b' ',
                "byte {index} must map onto itself or onto a blank"
            );
        }
    }
    assert!(crate::preprocessor_recovery_views("class C { int X; }").is_empty());
}

#[test]
fn unrecognized_hash_directive_lines_stay_untouched() {
    let source = "class C {\n  void M() { Foo(1,\n#notadirective\n    2\n  ); }\n}\n";
    assert!(crate::preprocessor_recovery_views(source).is_empty());
    let tree = crate::parse(source);
    assert!(tree.root_node().has_error());
    assert!(analyze_default(source).issues.is_empty());
}

#[test]
fn clean_preprocessor_placement_keeps_the_ordinary_parse() {
    // Argument-boundary directives already parse; the direct tree must stay
    // authoritative (including its `preproc_*` nodes) so tree-visible
    // suppressions such as `#pragma warning disable` keep working.
    let source = "class C {\n  void M() { Foo(1,\n#if DEBUG\n    2\n#endif\n  ); }\n}\n";
    let tree = crate::parse(source);
    assert!(!tree.root_node().has_error());
    assert_eq!(
        crate::cst::collect_kinds(tree.root_node(), &["preproc_if"]).len(),
        1
    );
}

#[test]
fn malformed_input_without_directives_stays_fail_closed() {
    let source = "class C {\n  void M() { Foo(,); }\n}\n";
    let tree = crate::parse(source);
    assert!(tree.root_node().has_error());
    assert!(analyze_default(source).issues.is_empty());
}

#[test]
fn conditional_region_evaluates_to_the_default_configuration() {
    // Without `DEBUG` defined, the default-configuration view excludes the
    // `1 2` region entirely and the call becomes `Foo();`.
    let source = "class C {\n  void M() { Foo(\n#if DEBUG\n    1 2\n#endif\n    ); }\n}\n";
    let tree = crate::parse(source);
    assert!(
        !tree.root_node().has_error(),
        "{}",
        tree.root_node().to_sexp()
    );
    let report = analyze_default(source);
    assert!(
        with_key(&report, "csharpsquid:S2325").len() == 1,
        "the recovered default-configuration view must be analyzed: {:?}",
        report.issues
    );
}

#[test]
fn else_branch_keeps_the_alternative_in_the_default_view() {
    // The blanked view joins both branches into valid arguments, so it wins
    // and both magic numbers stay visible to the rules.
    let source = "class C {\n  void M() {\n    Foo(1,\n#if DEBUG\n    2\n#else\n    3\n#endif\n    );\n  }\n}\n";
    let tree = crate::parse(source);
    assert!(!tree.root_node().has_error());
    let report = analyze_default(source);
    let magic_numbers = with_key(&report, "csharpsquid:S109");
    assert_eq!(magic_numbers.len(), 2);
    assert_eq!(magic_numbers[0].range.start.line, 5);
    assert_eq!(magic_numbers[1].range.start.line, 7);
}

#[test]
fn recovered_input_with_residual_errors_still_emits_parseable_findings() {
    // Balanced directives plus an unrelated malformed argument list: no view
    // parses cleanly, but the recovered tree is analyzed tolerantly instead
    // of refusing the file, and the parseable `if` statement is reported.
    let source = "class C {\n  void M() {\n    Foo(1,\n#if DEBUG\n    2\n#endif\n    ,);\n    if (flag) ;\n  }\n}\n";
    let tree = crate::parse(source);
    assert!(tree.root_node().has_error());
    let report = analyze_default(source);
    let empty_statements = with_key(&report, "csharpsquid:S1116");
    assert_eq!(empty_statements.len(), 1);
    assert_eq!(empty_statements[0].range.start.line, 8);
}

#[test]
fn unbalanced_directives_stay_fail_closed() {
    let unterminated = "class C {\n  void M() {\n#if DEBUG\n    Gone();\n  }\n}\n";
    assert!(crate::preprocessor_recovery_views(unterminated).is_empty());
    let tree = crate::parse(unterminated);
    assert!(tree.root_node().has_error());
    assert!(analyze_default(unterminated).issues.is_empty());

    let stray_end = "class C { void M() { } }\n#endif\n";
    assert!(crate::preprocessor_recovery_views(stray_end).is_empty());
    assert!(analyze_default(stray_end).issues.is_empty());
}

/// Residual #328: Dapper's `SqlMapper.cs` also binds indexer elements with
/// the contextual keywords `type`/`param`/`field` (`[type] = value`).  The
/// vendored grammar lexed those words as `attribute_target_specifier`
/// keyword literals, so the element binding produced an ERROR node and the
/// analyzer refused the whole file even after the directive views
/// recovered.  The vendored repair (upstream tree-sitter-c-sharp#429) lists
/// the specifier keywords as reserved identifiers and prefers the
/// target-specifier reading only when `:` follows.
const ELEMENT_BINDING_WITH_SPECIFIER_KEYWORDS: &str = "\
namespace Dapper
{
    public static partial class SqlMapper
    {
        static void SetTypeMap(System.Type type, TypeMapEntry value)
        {
            SetTypeMap(new Dictionary<Type, TypeMapEntry>(41
#if NET6_0_OR_GREATER
                + 4 // {Date|Time}Only[?]
#endif
                )
            {
                [type] = value,
                [typeof(byte)] = TypeMapEntry.DoNotSetFieldValue,
            });
            if (type is null) ;
        }
    }
}
";

#[test]
fn element_binding_with_specifier_keywords_is_analyzed() {
    let tree = crate::parse(ELEMENT_BINDING_WITH_SPECIFIER_KEYWORDS);
    assert!(
        !tree.root_node().has_error(),
        "`[type] = value` element bindings must parse without recovered nodes: {}",
        tree.root_node().to_sexp()
    );
    assert_eq!(
        crate::cst::collect_kinds(tree.root_node(), &["element_binding_expression"]).len(),
        2,
        "both `[type] = value` and `[typeof(byte)] = …` must bind as indexer elements"
    );
    let report = analyze_default(ELEMENT_BINDING_WITH_SPECIFIER_KEYWORDS);
    let empty_statements = with_key(&report, "csharpsquid:S1116");
    assert_eq!(
        empty_statements.len(),
        1,
        "findings must be emitted from the analyzed tree: {:?}",
        report.issues
    );
    assert_eq!(empty_statements[0].range.start.line, 16);
}

#[test]
fn specifier_keywords_stay_identifiers_and_targets() {
    // Every attribute_target_specifier keyword that is also a legal C#
    // identifier must parse as an element-binding key, while the real
    // `[target: Attr]` syntax keeps its specifier node.  `event`/`return`
    // are real keywords and stay excluded from identifier positions.
    let source = "class C {\n  [field: System.NonSerialized]\n  int P { get; set; }\n  void M(int field, int method, int param, int property, int type, int typevar) {\n    var d = new System.Collections.Generic.Dictionary<int, int> {\n      [field] = method, [param] = property, [type] = typevar,\n    };\n  }\n}\n";
    let tree = crate::parse(source);
    assert!(
        !tree.root_node().has_error(),
        "{}",
        tree.root_node().to_sexp()
    );
    assert_eq!(
        crate::cst::collect_kinds(tree.root_node(), &["attribute_target_specifier"]).len(),
        1,
        "`[field: …]` must keep its attribute target specifier"
    );
    assert_eq!(
        crate::cst::collect_kinds(tree.root_node(), &["element_binding_expression"]).len(),
        3
    );
    let report = analyze_default(source);
    assert!(
        !report.issues.is_empty(),
        "the analyzed tree must still emit findings"
    );
}

#[test]
fn specifier_keywords_in_collection_expressions_stay_identifiers() {
    // `[type]` inside a C# 12 collection expression is an identifier
    // element, not a target specifier.
    let source = "class C {\n  void M(int type, int field) {\n    int[] xs = [type, field];\n    System.Console.Write(xs.Length);\n  }\n}\n";
    let tree = crate::parse(source);
    assert!(
        !tree.root_node().has_error(),
        "{}",
        tree.root_node().to_sexp()
    );
    assert_eq!(
        crate::cst::collect_kinds(tree.root_node(), &["collection_expression"]).len(),
        1
    );
}
