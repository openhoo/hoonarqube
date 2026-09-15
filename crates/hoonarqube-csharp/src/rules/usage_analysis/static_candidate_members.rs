use crate::CsLanguage;
use crate::cst::{base_simple_names, issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, MemberSymbol, UsageSymbols, declares_executable_code, has_contract_modifier,
    owner_is_partial, touches_instance_data,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2325 — members ignoring instance data can become
/// `static`. The reference flags public members too, so visibility is no
/// gate; safety comes from the contract exclusions instead: attributed
/// members, inheritance modifiers, partial owners, explicit interface
/// implementations, empty methods, members of generic types, and members
/// whose name a declared base could supply. Bases resolve only when every
/// entry is a known BCL interface whose member set the table below
/// enumerates — custom or unknown bases keep the member silent.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if !matches!(member.flavor, MemberFlavor::Method | MemberFlavor::Property)
            || !matches!(
                member.owner.kind(),
                "class_declaration" | "struct_declaration"
            )
            || has_explicit_interface_specifier(member.declaration)
            || !bases_resolve(member, source)
            || owner_is_partial(member.owner, source)
            || is_attributed(member.declaration, source)
            || has_modifier(&modifiers_of(member.declaration, source), "static")
            || has_contract_modifier(&modifiers_of(member.declaration, source))
            || !declares_executable_code(member.declaration)
            || is_empty_method(member)
            || is_framework_handler(member)
            || non_private_member_of_generic_type(member, source)
            || touches_instance_data(member, symbols)
            || calls_overloaded_sibling(member, symbols)
        {
            continue;
        }
        issues.push(issue(
            language,
            "S2325",
            format!("Make '{}' a static {}.", member.name, member.flavor.word()),
            range_of(member.anchor, source),
        ));
    }
    issues
}

/// Methods with an empty block (`void M() { }`) stay silent: the
/// reference's `IsEmptyMethod` exemption keeps them out even though they
/// technically qualify.
fn is_empty_method(member: &MemberSymbol<'_>) -> bool {
    if member.flavor != MemberFlavor::Method {
        return false;
    }
    let mut cursor = member.declaration.walk();
    member
        .declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "block")
        .is_some_and(|block| {
            let mut block_cursor = block.walk();
            block
                .children(&mut block_cursor)
                .all(|child| !child.is_named() || child.kind() == "comment")
        })
}

/// ASP.NET `Application_*`/`Session_*` handlers and other framework
/// entry points the reference whitelists by name.
fn is_framework_handler(member: &MemberSymbol<'_>) -> bool {
    member.flavor == MemberFlavor::Method
        && matches!(
            member.name,
            "Application_AuthenticateRequest"
                | "Application_BeginRequest"
                | "Application_End"
                | "Application_EndRequest"
                | "Application_Error"
                | "Application_Init"
                | "Application_Start"
                | "Session_End"
                | "Session_Start"
        )
}

/// Non-private members of generic types stay silent: the reference
/// excludes any member accessible outside a generic type because
/// consumers may call it through constructed instances.
fn non_private_member_of_generic_type(member: &MemberSymbol<'_>, source: &str) -> bool {
    let modifiers = modifiers_of(member.declaration, source);
    if !modifiers
        .iter()
        .any(|modifier| matches!(*modifier, "public" | "internal" | "protected"))
    {
        return false;
    }
    let mut cursor = member.owner.walk();
    member
        .owner
        .children(&mut cursor)
        .any(|child| child.kind() == "type_parameter_list")
}

/// Explicit interface implementations carry an
/// `explicit_interface_specifier` child and can never be `static`.
fn has_explicit_interface_specifier(declaration: Node<'_>) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .any(|child| child.kind() == "explicit_interface_specifier")
}

/// Whether every declared base is a known BCL interface whose members the
/// table enumerates, and `member.name` is not one of them. Unknown bases
/// (custom interfaces, base classes) could supply the member's contract,
/// so they keep the member silent.
fn bases_resolve(member: &MemberSymbol<'_>, source: &str) -> bool {
    base_simple_names(member.owner, source)
        .iter()
        .all(|base| match bcl_interface_members(base) {
            Some(members) => !members.contains(&member.name),
            None => false,
        })
}

/// Whether the member's body calls a same-named sibling overload, which
/// is an implicit `this` call `touches_instance_data` cannot see (it
/// skips same-name references to allow recursion).
fn calls_overloaded_sibling(member: &MemberSymbol<'_>, symbols: &UsageSymbols<'_>) -> bool {
    let has_overload = symbols.members.iter().any(|sibling| {
        sibling.owner.id() == member.owner.id()
            && sibling.name == member.name
            && sibling.declaration.id() != member.declaration.id()
    });
    if !has_overload {
        return false;
    }
    let span = member.declaration.byte_range();
    symbols.references.iter().any(|reference| {
        let reference_span = reference.node.byte_range();
        reference_span.start >= span.start
            && reference_span.end <= span.end
            && !reference.introduces_binding()
            && reference.name == member.name
    })
}

/// Member names of the BCL interfaces the analyzer can resolve without a
/// referenced-assembly model. Only interfaces whose complete member set
/// is fixed by the BCL belong here.
fn bcl_interface_members(base: &str) -> Option<&'static [&'static str]> {
    Some(match base {
        "IDisposable" => &["Dispose"],
        "IAsyncDisposable" => &["DisposeAsync"],
        "ICloneable" => &["Clone"],
        "IEnumerable" | "IEnumerator" => &["GetEnumerator", "MoveNext", "Reset", "Current"],
        "ICollection" | "IList" | "IDictionary" => &[
            "Add",
            "Clear",
            "Contains",
            "CopyTo",
            "Remove",
            "GetEnumerator",
            "Count",
            "IsReadOnly",
            "IsSynchronized",
            "SyncRoot",
            "Item",
            "IndexOf",
            "Insert",
            "RemoveAt",
            "IsFixedSize",
            "Keys",
            "Values",
            "ContainsKey",
            "TryGetValue",
        ],
        "IComparable" | "IEquatable" => &["CompareTo", "Equals"],
        "IFormattable" => &["ToString"],
        "INotifyPropertyChanged" => &["PropertyChanged"],
        "INotifyPropertyChanging" => &["PropertyChanging"],
        // `IDataReader`/`IDataRecord` inherit `IDisposable`, so `Dispose`
        // belongs to their member set too.
        "IDataReader" | "IDataRecord" => &[
            "Dispose",
            "Close",
            "GetSchemaTable",
            "NextResult",
            "Read",
            "Depth",
            "IsClosed",
            "RecordsAffected",
            "GetName",
            "GetDataTypeName",
            "GetFieldType",
            "GetValue",
            "GetValues",
            "GetOrdinal",
            "GetBoolean",
            "GetByte",
            "GetBytes",
            "GetChar",
            "GetChars",
            "GetGuid",
            "GetInt16",
            "GetInt32",
            "GetInt64",
            "GetFloat",
            "GetDouble",
            "GetString",
            "GetDecimal",
            "GetDateTime",
            "GetData",
            "IsDBNull",
            "FieldCount",
            "Item",
        ],
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2325_flags_public_members_ignoring_instance_data() {
        let report = analyze_default(
            "class Database : System.IDisposable\n{\n    public void Dispose() { }\n    public bool IsNew(object poco)\n    {\n        var pd = PocoData.ForType(poco.GetType());\n        return pd == null;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2325");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s2325_flags_arrow_bodied_members() {
        let report = analyze_default("class C\n{\n    public int IgnoredProperty => 1;\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S2325").len(), 1);
    }

    #[test]
    fn s2325_ignores_empty_and_generic_owner_members() {
        let report = analyze_default(
            "class C\n{\n    public void Reset() { }\n}\nclass G<T>\n{\n    public T Echo(T value) { return value; }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2325").is_empty());
    }

    #[test]
    fn s2325_ignores_members_implementing_known_bcl_interfaces() {
        let report = analyze_default(
            "class R : System.Data.IDataReader\n{\n    public void Dispose() { }\n    public void Close() { }\n    public bool Read() { return true; }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2325").is_empty());
    }

    #[test]
    fn s2325_ignores_members_behind_unknown_bases() {
        let report = analyze_default(
            "class C : ICustomContract\n{\n    public void Run() { System.Console.WriteLine(1); }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2325").is_empty());
    }

    #[test]
    fn s2325_ignores_members_calling_same_named_overloads() {
        let report = analyze_default(
            "class Database : System.IDisposable\n{\n    public void Dispose() { }\n    public bool IsNew(string key, object poco) { return poco == null; }\n    public bool IsNew(object poco)\n    {\n        var pd = PocoData.ForType(poco.GetType());\n        return IsNew(pd.PrimaryKey, poco);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2325").len(), 1);
    }

    #[test]
    fn s2325_ignores_explicit_interface_implementations() {
        let report = analyze_default(
            "class C : System.Collections.Generic.IDictionary<string, object>\n{\n    System.Collections.Generic.ICollection<string> System.Collections.Generic.IDictionary<string, object>.Keys\n    {\n        get { return null; }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2325").is_empty());
    }
}
