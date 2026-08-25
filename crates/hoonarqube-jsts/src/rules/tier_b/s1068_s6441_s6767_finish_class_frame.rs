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
    /// Whether `name` was used inside this very class or somewhere outside
    /// any class (conservative for duck-typed / detached-method patterns);
    /// a same-named member used inside an unrelated class does not suppress.
    fn was_used(uses: &[(String, Option<usize>)], name: &str, frame_id: usize) -> bool {
        uses.iter().any(|(used, context)| {
            used == name && (*context == Some(frame_id) || context.is_none())
        })
    }

    pub(crate) fn finish_class_frame(&mut self, frame: &ClassFrame) {
        let component = frame
            .super_name
            .as_deref()
            .is_some_and(|base| base == "Component" || base == "PureComponent")
            || frame.methods.iter().any(|(name, _)| name == "render");
        for (name, span) in &frame.private_members {
            if !Self::was_used(&self.used_properties, name, frame.frame_id) {
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
            if !Self::was_used(&self.used_properties, name, frame.frame_id) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6441",
                    &format!("The component method '{name}' is never referenced."),
                    *span,
                );
            }
        }
        for (name, span) in &frame.prop_type_keys {
            if !Self::was_used(&self.props_accessed, name, frame.frame_id) {
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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1068_usage_in_sibling_class_does_not_suppress_finding() {
        // Only class B touches `#data`; class A's private member stays unused.
        let flagged = js_keys(
            "class A { #data = 1; read() { return 2; } }\n\
             class B { #data = 5; read() { return this.#data; } }\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S1068"), 1);
    }

    #[test]
    fn s6441_method_use_in_sibling_class_does_not_suppress_finding() {
        // `this.go()` runs inside B, so it attributes to B's frame only;
        // A's same-named method stays unused and must be flagged.
        let source = "class A extends Component { go() {} render() { return null; } }\n\
                      class B extends Component { go() {} render() { this.go(); } }\n";
        let flagged = js_keys(source);
        assert_eq!(count_key(&flagged, "javascript:S6441"), 1);
    }

    #[test]
    fn s6767_prop_type_key_use_in_sibling_class_does_not_suppress_finding() {
        let source = "class A extends Component { static propTypes = { shape: null }; render() { return null; } }\n\
                      class B extends Component { render() { return this.props.shape; } }\n";
        let flagged = js_keys(source);
        assert_eq!(count_key(&flagged, "javascript:S6767"), 1);
    }

    #[test]
    fn detached_outside_class_usage_still_suppresses_findings() {
        let source = "class A extends Component { go() {} render() { return null; } }\n\
                      const a = new A();\n\
                      a.go();\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S6441"), 0);
    }
}
