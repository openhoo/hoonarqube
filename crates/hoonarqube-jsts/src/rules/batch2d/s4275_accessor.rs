use super::collectors::{ClassAccessorCollector, FieldAccessScanner};
use crate::support::RuleScope;
use oxc_ast::ast::FunctionBody;
use oxc_ast_visit::Visit;
use oxc_span::Span;

impl ClassAccessorCollector<'_> {
    /// `S4275`: accessors should touch the field their name declares.
    pub(crate) fn check_accessor(
        &mut self,
        name: Option<&str>,
        key_span: Span,
        is_setter: bool,
        body: Option<&FunctionBody<'_>>,
    ) {
        let (Some(name), Some(body)) = (name, body) else {
            return;
        };
        let mut scanner = FieldAccessScanner {
            field: name,
            read: false,
            written: false,
        };
        scanner.visit_function_body(body);
        let satisfied = if is_setter {
            scanner.written
        } else {
            scanner.read
        };
        if !satisfied {
            let message = if is_setter {
                format!("Verify that this setter assigns the \"{name}\" field.")
            } else {
                format!("Verify that this getter accesses the \"{name}\" field.")
            };
            self.sink
                .emit_span(RuleScope::Both, "S4275", &message, key_span);
        }
    }
}
