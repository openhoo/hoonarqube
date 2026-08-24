use super::walker::{ReactCollector, duplicated_key_name};
use crate::support::RuleScope;
use oxc_ast::ast::MethodDefinition;
use oxc_ast::ast::MethodDefinitionKind;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6791`: legacy lifecycle method names on class bodies.
    pub(crate) fn check_legacy_lifecycle(&mut self, method: &MethodDefinition<'_>) {
        if method.kind == MethodDefinitionKind::Constructor {
            return;
        }
        let Some(name) = duplicated_key_name(&method.key) else {
            return;
        };
        if LEGACY_LIFECYCLE_METHODS.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6791",
                "This legacy lifecycle method is deprecated; use the 'UNSAFE_'-prefixed version or refactor.",
                method.key.span(),
            );
        }
    }
}

/// `S6791`: pre-16.3 lifecycle names superseded by `UNSAFE_`-prefixed ones.
pub(crate) const LEGACY_LIFECYCLE_METHODS: [&str; 3] = [
    "componentWillMount",
    "componentWillReceiveProps",
    "componentWillUpdate",
];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6791_flags_legacy_component_will_mount() {
        let findings = js_keys("class A extends B {\n  componentWillMount() {}\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6791"), 1);
    }

    #[test]
    fn s6791_allows_unsafe_prefixed_variant() {
        let findings = js_keys("class A extends B {\n  UNSAFE_componentWillMount() {}\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6791"), 0);
    }

    #[test]
    fn s6791_flags_legacy_component_will_receive_props() {
        let findings = js_keys("class A {\n  componentWillReceiveProps() {}\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6791"), 1);
    }
}
