//! Test suite part; the full suite spans `tests/*.rs`.

use super::{PathBuf, analyze_default, analyze_options, with_key};
use crate::AnalyzerOptions;
use crate::ProjectTypeIndex;
use crate::semantic::SourceSnapshot;
use std::sync::Arc;

const BULK_COPY: &str = "namespace Tools\n{\n    public class BulkCopy\n    {\n        public static BulkCopy Create(DbConnection connection)\n        {\n            return new BulkCopy();\n        }\n    }\n}\n";
const DYNAMIC_BULK_COPY: &str = "namespace Tools\n{\n    internal sealed class DynamicBulkCopy : BulkCopy\n    {\n        internal static BulkCopy? Create(object? wrapped)\n        {\n            return null;\n        }\n    }\n}\n";

fn options_with_index(sources: &[(&str, &str)]) -> AnalyzerOptions {
    let snapshots: Vec<SourceSnapshot> = sources
        .iter()
        .map(|(path, source)| SourceSnapshot::new(PathBuf::from(path), *source))
        .collect();
    AnalyzerOptions {
        project_type_index: Some(Arc::new(ProjectTypeIndex::build(&snapshots))),
        ..AnalyzerOptions::default()
    }
}

#[test]
fn s4019_reports_cross_file_hidden_base_methods() {
    let options = options_with_index(&[
        ("BulkCopy.cs", BULK_COPY),
        ("DynamicBulkCopy.cs", DYNAMIC_BULK_COPY),
    ]);
    let report = analyze_options(DYNAMIC_BULK_COPY, &options);
    let flagged = with_key(&report, "csharpsquid:S4019");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(
        flagged[0].message,
        "Remove or rename that method because it hides 'BulkCopy.Create(DbConnection)'."
    );

    let base_report = analyze_options(BULK_COPY, &options);
    assert!(
        with_key(&base_report, "csharpsquid:S4019").is_empty(),
        "the base file itself stays clean"
    );
}

#[test]
fn s4019_cross_file_lookup_ignores_unrelated_overloads() {
    let base = "namespace Tools\n{\n    public interface IReader\n    {\n        object Read(Type kind, object raw);\n    }\n\n    public class Reader : IReader\n    {\n        public object Read(object raw) => raw;\n        object IReader.Read(Type kind, object raw) => Read(raw);\n    }\n}\n";
    let derived = "namespace Tools\n{\n    public class StringReader : Reader\n    {\n        public object Read(string raw) => raw;\n    }\n}\n";
    let options = options_with_index(&[("Reader.cs", base), ("StringReader.cs", derived)]);
    let report = analyze_options(derived, &options);
    assert!(
        with_key(&report, "csharpsquid:S4019").is_empty(),
        "an arity-mismatched overload is not a hidden base method"
    );
}

#[test]
fn s4019_cross_file_inheritance_extends_parameter_coverage() {
    let base = "namespace Shapes\n{\n    public class Canvas\n    {\n        public void Paint(Circle circle) { }\n    }\n\n    public class Shape { }\n\n    public class Circle : Shape { }\n}\n";
    let derived = "namespace Shapes\n{\n    public class Poster : Canvas\n    {\n        public void Paint(Shape shape) { }\n    }\n}\n";
    let options = options_with_index(&[("Canvas.cs", base), ("Poster.cs", derived)]);
    let report = analyze_options(derived, &options);
    let flagged = with_key(&report, "csharpsquid:S4019");
    assert_eq!(flagged.len(), 1);
    assert_eq!(
        flagged[0].message,
        "Remove or rename that method because it hides 'Canvas.Paint(Circle)'."
    );
}

#[test]
fn s4019_without_project_index_base_resolution_stays_file_local() {
    let report = analyze_options(DYNAMIC_BULK_COPY, &AnalyzerOptions::default());
    assert!(
        with_key(&report, "csharpsquid:S4019").is_empty(),
        "cross-file resolution requires the project index; per-file behavior is unchanged"
    );
}

#[test]
fn s4019_implicit_interface_implementations_are_not_hidden_base_methods() {
    let interface = "namespace Mapping\n{\n    public interface ITypeMap\n    {\n        System.Reflection.ConstructorInfo? FindConstructor(string[] names, System.Type[] types);\n\n        System.Reflection.ConstructorInfo? FindExplicitConstructor();\n    }\n}\n";
    let implementation = "namespace Mapping\n{\n    public sealed class CustomMap : ITypeMap\n    {\n        public System.Reflection.ConstructorInfo? FindConstructor(string[] names, System.Type[] types) => null;\n\n        public System.Reflection.ConstructorInfo? FindExplicitConstructor() => null;\n    }\n}\n";
    let options =
        options_with_index(&[("ITypeMap.cs", interface), ("CustomMap.cs", implementation)]);
    let report = analyze_options(implementation, &options);
    assert!(
        with_key(&report, "csharpsquid:S4019").is_empty(),
        "interface members are implemented, never hidden"
    );

    // File-local resolution behaves the same without a project index.
    let local = analyze_default(&format!("{interface}{implementation}"));
    assert!(with_key(&local, "csharpsquid:S4019").is_empty());
}

#[test]
fn s4019_generic_name_collision_does_not_flag_own_members() {
    let base = "namespace Tools\n{\n    public class Identity\n    {\n        public virtual int TypeCount => 0;\n    }\n}\n";
    let derived = "namespace Tools\n{\n    internal sealed class Identity<TFirst, TSecond> : Identity\n    {\n        private static int CountNonTrivial(out int hashCode)\n        {\n            hashCode = 0;\n\n            return 0;\n        }\n    }\n}\n";
    let options = options_with_index(&[("Identity.cs", base), ("IdentityGeneric.cs", derived)]);
    let report = analyze_options(derived, &options);
    assert!(
        with_key(&report, "csharpsquid:S4019").is_empty(),
        "a type never hides members of its own declaration"
    );
}

#[test]
fn s4019_generic_derived_still_hides_arity_zero_base_methods() {
    let base = "namespace Tools\n{\n    public class Identity\n    {\n        public void Refresh() { }\n    }\n}\n";
    let derived = "namespace Tools\n{\n    internal sealed class Identity<TFirst, TSecond> : Identity\n    {\n        public void Refresh() { }\n    }\n}\n";
    let options = options_with_index(&[("Identity.cs", base), ("IdentityGeneric.cs", derived)]);
    let report = analyze_options(derived, &options);
    let flagged = with_key(&report, "csharpsquid:S4019");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(
        flagged[0].message,
        "Remove or rename that method because it hides 'Identity.Refresh()'."
    );
}

#[test]
fn s4019_interface_sharing_base_simple_name_contributes_no_candidates() {
    // A class base and an interface may share a simple name across
    // namespaces; only the class declaration's members are candidates.
    let class_base = "namespace A\n{\n    public class Base\n    {\n        public void Refresh() { }\n    }\n}\n";
    let interface_base =
        "namespace B\n{\n    public interface Base\n    {\n        void Refresh();\n    }\n}\n";
    let derived = "namespace C\n{\n    public sealed class Impl : A.Base\n    {\n        public void Refresh() { }\n    }\n}\n";
    let options = options_with_index(&[
        ("Base.cs", class_base),
        ("IBase.cs", interface_base),
        ("Impl.cs", derived),
    ]);
    let report = analyze_options(derived, &options);
    let flagged = with_key(&report, "csharpsquid:S4019");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}
