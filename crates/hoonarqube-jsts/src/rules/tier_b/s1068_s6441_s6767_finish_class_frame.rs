use super::collectors::{ClassFrame, ClassRuleCollector};
use crate::support::RuleScope;

/// React lifecycle names invoked by the framework itself (`S6441`).
const LIFECYCLE_METHODS: &[&str] = &[
    "constructor",
    "render",
    "componentDidMount",
    "componentDidUpdate",
    "componentWillUnmount",
    "componentDidCatch",
    "getDerivedStateFromProps",
    "getSnapshotBeforeUpdate",
    "shouldComponentUpdate",
];

impl ClassRuleCollector<'_> {
    pub(crate) fn finish_class_frame(&mut self, frame: &ClassFrame) {
        let component = frame
            .super_name
            .as_deref()
            .is_some_and(|base| base == "Component" || base == "PureComponent")
            || frame.methods.iter().any(|(name, _)| name == "render");
        for (name, span) in &frame.private_members {
            if !self.used_properties.iter().any(|used| used == name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1068",
                    &format!("Remove this unused private class member '{name}'."),
                    *span,
                );
            }
        }
        if !component {
            return;
        }
        for (name, span) in &frame.methods {
            if LIFECYCLE_METHODS.contains(&name.as_str()) {
                continue;
            }
            if !self.used_properties.iter().any(|used| used == name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6441",
                    &format!("The component method '{name}' is never referenced."),
                    *span,
                );
            }
        }
        for (name, span) in &frame.prop_type_keys {
            if !self.props_accessed.iter().any(|used| used == name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6767",
                    &format!("Remove the unused prop type entry '{name}'."),
                    *span,
                );
            }
        }
    }
}
