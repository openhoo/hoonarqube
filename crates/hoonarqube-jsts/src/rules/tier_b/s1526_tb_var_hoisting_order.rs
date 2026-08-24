// Rule module s1526_tb_var_hoisting_order (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S1526 (JS only) — identifiers read textually before their `var`
/// declarator (hoisting order).
pub(crate) fn check_tb_var_hoisting_order(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind != TbKind::Var {
            continue;
        }
        let name = binding.name;
        for read in binding
            .reads
            .iter()
            .filter(|read| read.end < binding.decl.start)
            .copied()
        {
            sink.emit_span(
                RuleScope::JsOnly,
                "S1526",
                &format!("Move the declaration of '{name}' above this usage; 'var' is hoisted."),
                read,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn var_read_before_its_declarator_flagged() {
        let flagged = js("function f() {\n  console.log(hoisted);\n  var hoisted = 1;\n}\nf();\n");
        assert_eq!(filtered(&flagged, "S1526").len(), 1);
        let clean = js("function f() {\n  var hoisted = 1;\n  console.log(hoisted);\n}\nf();\n");
        assert_eq!(filtered(&clean, "S1526").len(), 0);
    }
}
