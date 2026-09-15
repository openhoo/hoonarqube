// Rule module s2999_tb_constructor_resolution (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S2999 — `new` applied to a value that provably lacks constructor
/// semantics. Suspects on unknown callees (imports, requires, parameters)
/// are never emitted: Sonar's reference run only reports provable
/// non-constructors.
pub(crate) fn check_tb_constructor_resolution(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for &(binding, span) in &model.news {
        let known_constructor = matches!(
            model.bindings[binding].kind,
            TbKind::Function | TbKind::Class
        );
        if !known_constructor && model.bindings[binding].non_constructible {
            let name = model.bindings[binding].name;
            sink.emit_span(
                RuleScope::Both,
                "S2999",
                &format!("Remove 'new': '{name}' does not hold a constructor."),
                span,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn new_on_non_constructor_binding_flagged() {
        let flagged = js("const make = () => 1;\nnew make();\n");
        assert_eq!(filtered(&flagged, "S2999").len(), 1);
        let literal = js("const thing = {};\nnew thing();\n");
        assert_eq!(filtered(&literal, "S2999").len(), 1);
        let namespace = js("import * as ns from 'mod';\nnew ns();\n");
        assert_eq!(filtered(&namespace, "S2999").len(), 1);
        let clean = js("class Box {}\nnew Box();\nfunction Factory() {}\nnew Factory();\n");
        assert_eq!(filtered(&clean, "S2999").len(), 0);
    }

    #[test]
    fn unknown_callees_are_never_suspected() {
        // Issue #378: required/imported constructors and opaque values must
        // stay silent; only provable non-constructors are reported.
        let required =
            js("const StreamBuf = require('stream-buf');\nconst sb = new StreamBuf();\n");
        assert_eq!(filtered(&required, "S2999").len(), 0);
        let imported = js("import Cell from './cell';\nconst c = new Cell();\n");
        assert_eq!(filtered(&imported, "S2999").len(), 0);
        let parameter = js("export function build(Ctor) {\n  return new Ctor();\n}\n");
        assert_eq!(filtered(&parameter, "S2999").len(), 0);
        let function_value = js("const Box = function () {};\nnew Box();\n");
        assert_eq!(filtered(&function_value, "S2999").len(), 0);
    }
}
