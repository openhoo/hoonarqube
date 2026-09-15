use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::symbol_table::UsageSymbols;
use hoonarqube_ir::Issue;

/// csharpsquid:S3218 — nested types redeclaring an outer static member
/// hide it and mislead readers; methods of nested types shadowing any
/// enclosing type's member name are reported with the reference's method
/// wording (all 12 dapper oracle sites, including the nested
/// `ITypeHandler.Parse` interface member).
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_symbol in &symbols.types {
        let Some(mut ancestor) = type_symbol.parent else {
            continue;
        };
        let mut outer_names = symbols.static_members_of(ancestor);
        while let Some(grandparent) = symbols
            .types
            .iter()
            .find(|candidate| candidate.declaration == ancestor)
            .and_then(|candidate| candidate.parent)
        {
            ancestor = grandparent;
            outer_names.extend(symbols.static_members_of(grandparent));
        }
        for member in symbols.static_members_of(type_symbol.declaration) {
            if outer_names.iter().any(|outer| outer.name == member.name) {
                issues.push(issue(
                    language,
                    "S3218",
                    "Rename this field to not shadow the outer class' member with the same name.",
                    range_of(member.anchor, source),
                ));
            }
        }
    }
    for member in &symbols.members {
        if member.flavor != crate::symbol_table::MemberFlavor::Method {
            continue;
        }
        let Some(mut ancestor) = symbols
            .types
            .iter()
            .find(|candidate| candidate.declaration == member.owner)
            .and_then(|candidate| candidate.parent)
        else {
            continue;
        };
        // The reference reports shadowing of static outer members only: the
        // 12 oracle sites all shadow statics (SqlMapper.Parse<T>/GetValue<T>/
        // ReadRow<T>/Format, the static extension helpers), while
        // instance-member shadowing (PetaPoco's nested
        // ShareableConnection.Dispose against Database.Dispose, LegacyTests'
        // nested Tests.RunAsync) stays unreported.
        let mut shadows = symbols
            .static_members_of(ancestor)
            .iter()
            .any(|outer| outer.name == member.name);
        while let Some(grandparent) = symbols
            .types
            .iter()
            .find(|candidate| candidate.declaration == ancestor)
            .and_then(|candidate| candidate.parent)
        {
            ancestor = grandparent;
            shadows |= symbols
                .static_members_of(grandparent)
                .iter()
                .any(|outer| outer.name == member.name);
        }
        if shadows {
            issues.push(issue(
                language,
                "S3218",
                "Rename this method to not shadow the outer class member with the same name.",
                range_of(member.anchor, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod method_facet_tests {
    use crate::tests::{analyze_default, with_key};

    /// dapper Dapper.ProviderTools/DbConnectionExtensions.cs:45/56/63: a
    /// nested helper class redeclares the outer static class' method names.
    #[test]
    fn s3218_flags_nested_methods_shadowing_outer_methods() {
        let report = analyze_default(
            "public static class Extensions\n{\n    public static bool TryClearPool(object c) => true;\n    private sealed class Helpers\n    {\n        public bool TryClearPool(object c) => true;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3218");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Rename this method to not shadow the outer class member with the same name."
        );
    }

    /// Shadowing works through several nesting levels: dapper's
    /// `DapperRowPropertyDescriptor.GetValue` (98) sits inside `DapperRow`
    /// inside `SqlMapper`, which declares `GetValue<T>`.
    #[test]
    fn s3218_flags_method_shadowing_through_intermediate_nesting() {
        let report = analyze_default(
            "static class Mapper\n{\n    internal static T GetValue<T>(object o) => default;\n    sealed class Row\n    {\n        sealed class Descriptor\n        {\n            public override object GetValue(object component) => null;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3218").len(), 1);
    }

    /// dapper Dapper/SqlMapper.ITypeHandler.cs:26: nested interface members
    /// shadow too.
    #[test]
    fn s3218_flags_nested_interface_members() {
        let report = analyze_default(
            "static class Mapper\n{\n    internal static T Parse<T>(object o) => default;\n    interface IHandler\n    {\n        object Parse(Type destinationType, object value);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3218").len(), 1);
    }

    /// The reference spares instance outer members: `PetaPoco`'s nested
    /// `ShareableConnection.Dispose` against the non-static
    /// `Database.Dispose` and `LegacyTests`' nested `Tests.RunAsync` against
    /// `LegacyTests.RunAsync` are both unreported there.
    #[test]
    fn s3218_instance_outer_members_stay_clear() {
        let report = analyze_default(
            "public class Database : System.IDisposable\n{\n    public void Dispose() { }\n    private sealed class ShareableConnection : System.IDisposable\n    {\n        public void Dispose() { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3218").is_empty());
    }

    /// Methods in top-level types have nothing to shadow, and nested methods
    /// with unique names stay clear.
    #[test]
    fn s3218_unique_names_and_top_level_methods_stay_clear() {
        let report = analyze_default(
            "static class Mapper\n{\n    internal static T Parse<T>(object o) => default;\n    internal static int Compute() => 1;\n    sealed class Row\n    {\n        public int Sum() => 1;\n        public void InnerParse() { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3218").is_empty());
    }
}
