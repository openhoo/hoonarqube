// Rule module s2376_class_accessor_pairing (generated).
use crate::support::{IssueSink, RuleScope, property_key_name};
use oxc_ast::ast::{ClassElement, MethodDefinitionKind};
use oxc_span::{GetSpan, Span};

/// Whether any class element is a setter whose name has no matching getter;
/// flags each unmatched setter (`S2376` with the reference defaults:
/// `setWithoutGet`, `getWithoutSet` off, so intentionally setter-less
/// derived getters are never suspects).
pub(crate) fn check_class_setter_pairing(sink: &mut IssueSink<'_>, elements: &[ClassElement<'_>]) {
    let getter_names: Vec<Option<&str>> = elements
        .iter()
        .filter_map(|element| match element {
            ClassElement::MethodDefinition(method) if method.kind == MethodDefinitionKind::Get => {
                Some(property_key_name(&method.key))
            }
            _ => None,
        })
        .collect();
    let setters: Vec<(Option<&str>, Span)> = elements
        .iter()
        .filter_map(|element| match element {
            ClassElement::MethodDefinition(method) if method.kind == MethodDefinitionKind::Set => {
                Some((property_key_name(&method.key), method.key.span()))
            }
            _ => None,
        })
        .collect();
    for (name, span) in setters {
        if !getter_names.contains(&name) {
            sink.emit_span(
                RuleScope::Both,
                "S2376",
                "Add a getter matching this setter.",
                span,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn setters_without_getters_are_flagged_on_classes_and_objects() {
        let class_unpaired = js_keys("class A {\n  set value(next) {}\n}\n");
        assert_eq!(count_key(&class_unpaired, "javascript:S2376"), 1);
        let class_paired =
            js_keys("class A {\n  get value() {\n    return 1;\n  }\n  set value(next) {}\n}\n");
        assert_eq!(count_key(&class_paired, "javascript:S2376"), 0);

        let object_unpaired =
            js_keys("const obj = {\n  set count(next) {\n    this.n = next;\n  }\n};\n");
        assert_eq!(count_key(&object_unpaired, "javascript:S2376"), 1);
    }

    #[test]
    fn s2376_spares_paired_accessors_and_derived_setter_less_getters() {
        // Issue #380: a derived, intentionally setter-less getter is not a
        // finding under the reference defaults.
        let getter_only = js_keys("class A {\n  get value() {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&getter_only, "javascript:S2376"), 0);

        let object_paired = js_keys(
            "const obj = {\n  get count() {\n    return this.n;\n  },\n  set count(next) {},\n};\n",
        );
        assert_eq!(count_key(&object_paired, "javascript:S2376"), 0);
    }

    #[test]
    fn s2376_flags_each_unpaired_setter_separately() {
        let mixed = js_keys(
            "class A {\n  get a() {\n    return 1;\n  }\n  set a(v) {}\n  set b(v) {}\n  set c(v) {}\n}\n",
        );
        assert_eq!(count_key(&mixed, "javascript:S2376"), 2);
    }
}
