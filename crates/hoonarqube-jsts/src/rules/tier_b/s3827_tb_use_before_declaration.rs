// Rule module s3827_tb_use_before_declaration (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S3827 (JS only) — `let`/`const`/class/function used before declaration.
pub(crate) fn check_tb_use_before_declaration(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        let ordered = matches!(
            binding.kind,
            TbKind::Let | TbKind::Const | TbKind::Class | TbKind::Function
        );
        if !ordered {
            continue;
        }
        let name = binding.name;
        let reads = binding
            .reads
            .iter()
            .filter(|read| read.start < binding.decl.start)
            .copied();
        let writes = match binding.kind {
            // Function bodies hoist; only textual call order is style noise.
            TbKind::Function => Vec::new(),
            _ => binding
                .writes
                .iter()
                .filter(|write| write.start < binding.decl.start)
                .copied()
                .collect(),
        };
        for site in reads.into_iter().chain(writes) {
            sink.emit_span(
                RuleScope::JsOnly,
                "S3827",
                &format!("Move the declaration of '{name}' above this usage."),
                site,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn use_before_declaration_flagged_for_let_and_function_calls() {
        let source = "function f() {\n  early = 1;\n  let early = 2;\n}\nf();\n";
        assert_eq!(filtered(&js(source), "S3827").len(), 1);
        let calls = js("later();\nfunction later() {}\n");
        assert_eq!(filtered(&calls, "S3827").len(), 1);
    }
}
