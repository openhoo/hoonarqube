// `S5958` assertion-call coverage (issue #389). The catch-block shape
// lives in `s5958_catch_without_assertion`; this module covers the
// assertion-call shapes: chai chains that catch an exception without
// pinning its type (bare `.throw()`, or `.throw(Error)` capped at the
// unspecific base class) and bare `assert.throws(fn)` calls. Reference
// semantics: the pinned exceljs oracle flags `.to.throw(Error)` alongside
// the bare form while exempting message-string and variable arguments.
use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::support::{RuleScope, identifier_name};
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

impl TestFrameworkCollector<'_, '_> {
    /// `S5958`: assertion calls that catch an exception without checking
    /// which one is thrown.
    pub(crate) fn check_throw_assertion_type(&mut self, it: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &it.callee else {
            return;
        };
        match member.property.name.as_str() {
            // chai: `expect(fn).to.throw(...)`, `x.should.throw(...)`.
            "throw" => {
                let chai_chained = matches!(
                    &member.object,
                    Expression::StaticMemberExpression(chain)
                        if chain.property.name == "to" || chain.property.name == "should"
                );
                if chai_chained && throw_argument_is_unspecific(it) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5958",
                        "Test should check which exception is thrown.",
                        member.property.span(),
                    );
                }
            }
            // node assert: bare `assert.throws(fn)` / `assert.rejects(fn)`.
            "throws" | "rejects"
                if identifier_name(&member.object) == Some("assert") && it.arguments.len() < 2 =>
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5958",
                    "Test should check which exception is thrown.",
                    member.property.span(),
                );
            }
            _ => {}
        }
    }
}

/// Whether the chai throw assertion leaves the expected exception
/// unspecified: no argument at all, or only the unspecific base `Error`.
fn throw_argument_is_unspecific(call: &CallExpression<'_>) -> bool {
    call.arguments.is_empty()
        || call.arguments.iter().any(|argument| {
            matches!(
                argument.as_expression(),
                Some(Expression::Identifier(identifier)) if identifier.name == "Error"
            )
        })
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s5958_flags_chai_throw_without_specific_type() {
        let bare = "describe('x', () => {\n  it('throws', () => {\n    expect(() => f()).to.throw();\n  });\n});\n";
        assert_eq!(count_key(&test_file_keys(bare), "javascript:S5958"), 1);

        let base_error = "describe('x', () => {\n  it('throws', () => {\n    expect(() => f()).to.throw(Error);\n  });\n});\n";
        assert_eq!(
            count_key(&test_file_keys(base_error), "javascript:S5958"),
            1
        );

        let should_form =
            "describe('x', () => {\n  it('throws', () => {\n    ({}).should.throw();\n  });\n});\n";
        assert_eq!(
            count_key(&test_file_keys(should_form), "javascript:S5958"),
            1
        );
    }

    #[test]
    fn s5958_keeps_specific_chai_assertions_silent() {
        let message = "describe('x', () => {\n  it('throws', () => {\n    expect(() => f()).to.throw('boom');\n  });\n});\n";
        assert_eq!(count_key(&test_file_keys(message), "javascript:S5958"), 0);

        let subclass = "describe('x', () => {\n  it('throws', () => {\n    expect(() => f()).to.throw(TypeError);\n  });\n});\n";
        assert_eq!(count_key(&test_file_keys(subclass), "javascript:S5958"), 0);

        let variable = "describe('x', () => {\n  it('throws', () => {\n    expect(() => f()).to.throw(expectedError);\n  });\n});\n";
        assert_eq!(count_key(&test_file_keys(variable), "javascript:S5958"), 0);
    }

    #[test]
    fn s5958_flags_only_bare_assert_throws() {
        let bare = "describe('x', () => {\n  it('throws', () => {\n    assert.throws(() => f());\n  });\n});\n";
        assert_eq!(count_key(&test_file_keys(bare), "javascript:S5958"), 1);

        let typed = "describe('x', () => {\n  it('throws', () => {\n    assert.throws(() => f(), TypeError);\n  });\n});\n";
        assert_eq!(count_key(&test_file_keys(typed), "javascript:S5958"), 0);
    }
}
