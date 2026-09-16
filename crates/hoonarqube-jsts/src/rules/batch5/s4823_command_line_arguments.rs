use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::support::RuleScope;
use crate::support::member_object;
use crate::support::member_root_name;
use crate::support::static_property_name;
use crate::support::unparenthesized;
use oxc_ast::ast::{Expression, MemberExpression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4823`: command-line argument accesses worth reviewing.
    /// `process.argv[0]`/ `process.argv[1]` are the runtime binary and the
    /// entrypoint script path — not user-controlled arguments — so reads of
    /// them (e.g. the `argv[1] === import.meta.filename` main-module idiom)
    /// are exempt. `process.argv`, `argv[2+]`, and `execArgv` still flag.
    pub(crate) fn check_command_line_arguments(&mut self, it: &MemberExpression<'_>) {
        if member_root_name(it) == Some("process")
            && matches!(static_property_name(it), Some("argv" | "execArgv"))
            && !self
                .argv_entrypoint_spans
                .contains(&(it.span().start, it.span().end))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4823",
                "Make sure that command line arguments are used safely here.",
                it.span(),
            );
        }
    }

    /// Records the inner `process.argv` span of `process.argv[N]` for the
    /// `S4823` entrypoint exemption when `N` is the literal `0` or `1`.
    pub(crate) fn note_argv_entrypoint_read(&mut self, it: &MemberExpression<'_>) {
        let MemberExpression::ComputedMemberExpression(computed) = it else {
            return;
        };
        let Expression::NumericLiteral(index) = unparenthesized(&computed.expression) else {
            return;
        };
        // `process.argv[0]`/`process.argv[1]` are the runtime binary and the
        // entrypoint path — not user-supplied arguments.
        if !(0.0..2.0).contains(&index.value) || index.value.fract() > 0.0 {
            return;
        }
        let Some(inner_member) = unparenthesized(member_object(it)).as_member_expression() else {
            return;
        };
        if member_root_name(inner_member) == Some("process")
            && matches!(static_property_name(inner_member), Some("argv"))
        {
            let inner = inner_member.span();
            self.argv_entrypoint_spans.insert((inner.start, inner.end));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s4823_flags_user_argv_reads_but_spares_entrypoint_idiom() {
        // #523: `process.argv[1]` is the entrypoint path; comparing it
        // against `import.meta.filename` is the main-module idiom, not a
        // command-line argument read.
        let entrypoint = ts_keys(
            "import { fileURLToPath } from \"node:url\";\nconst isMain = process.argv[1] === fileURLToPath(import.meta.url);\nconsole.log(isMain);\n",
        );
        assert_eq!(count_key(&entrypoint, "typescript:S4823"), 0);

        // Reading user-supplied arguments still flags.
        let user_arg = ts_keys("const target = process.argv[2];\nconsole.log(target);\n");
        assert_eq!(count_key(&user_arg, "typescript:S4823"), 1);
    }
}
