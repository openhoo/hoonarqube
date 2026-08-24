use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::property_key_name;
use oxc_ast::ast::TSSignature;
use oxc_span::GetSpan;

impl TsTypeCollector<'_, '_> {
    /// `S4136`: same-name method-signature overloads separated by unrelated
    /// signature kinds must be grouped together.
    pub(crate) fn check_overload_grouping(&mut self, members: &[TSSignature<'_>]) {
        let mut last_method_positions: Vec<(&str, usize)> = Vec::new();
        for (position, member) in members.iter().enumerate() {
            let TSSignature::TSMethodSignature(method) = member else {
                continue;
            };
            let Some(name) = property_key_name(&method.key) else {
                continue;
            };
            if let Some(entry) = last_method_positions
                .iter_mut()
                .find(|(seen_name, _)| *seen_name == name)
            {
                let previous = entry.1;
                if members[previous + 1..position]
                    .iter()
                    .any(|other| !matches!(other, TSSignature::TSMethodSignature(_)))
                {
                    self.sink.emit_span(
                        RuleScope::TsOnly,
                        "S4136",
                        "Group all overloaded signatures of this method together.",
                        method.span(),
                    );
                }
                entry.1 = position;
            } else {
                last_method_positions.push((name, position));
            }
        }
    }
}
