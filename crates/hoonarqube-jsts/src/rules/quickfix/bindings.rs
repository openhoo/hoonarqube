//! Semantic-safe quick fixes for bindings, imports, assertions, and typed members.
//!
//! Every candidate in this module is attached to an existing native finding.  The
//! native finding supplies the issue index; OXC's semantic model and AST provide
//! the eligibility proof and exact edit spans.  In particular, this module never
//! infers a binding from text or a method's name alone.

use std::collections::{HashMap, HashSet};

use hoonarqube_ir::Issue;
use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrayExpression, ArrowFunctionExpression, BinaryOperator, BindingIdentifier,
        BindingPattern, CallExpression, Expression, FormalParameter, FormalParameters, Function,
        FunctionType, ImportDeclaration, ImportDeclarationSpecifier, ImportDefaultSpecifier,
        ImportNamespaceSpecifier, ImportSpecifier, MethodDefinitionKind, PropertyDefinition,
        PropertyKind, Statement, StaticMemberExpression, TSAccessibility, TSType, TSTypeAnnotation,
        TSTypeOperatorOperator, UnaryOperator, VariableDeclarationKind, VariableDeclarator,
    },
};
use oxc_parser::{Kind, Token};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{GetSpan, Span};
use oxc_syntax::reference::ReferenceFlags;

use crate::context::AnalysisContext;

use super::{Candidate, candidate};

#[derive(Clone, Copy)]
struct Target {
    index: usize,
    rule: &'static str,
    span: Span,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArrayKind {
    Any,
    Number,
    String,
    BigInt,
}

/// Collect all supported binding-family suggestions in one semantic-node pass.
///
/// The caller builds `Semantic` with `with_build_nodes(true)`.  This is required
/// because resolved references and ancestor checks intentionally use its node
/// store rather than reparsing or scanning source text.
pub(super) fn collect<'a>(
    ctx: &AnalysisContext<'a>,
    semantic: &Semantic<'a>,
    issues: &[Issue],
) -> Vec<(usize, Candidate)> {
    let targets = issues
        .iter()
        .enumerate()
        .filter_map(|(index, issue)| {
            let rule = issue.rule_key.rsplit(':').next()?;
            let rule = match rule {
                "S1128" => "S1128",
                "S1172" => "S1172",
                "S1444" => "S1444",
                "S2871" => "S2871",
                "S2990" => "S2990",
                "S3415" => "S3415",
                "S4043" => "S4043",
                "S4322" => "S4322",
                "S6759" => "S6759",
                _ => return None,
            };
            Some(Target {
                index,
                rule,
                span: issue_span(ctx, issue)?,
            })
        })
        .collect::<Vec<_>>();
    if targets.is_empty() || semantic.nodes().is_empty() {
        return Vec::new();
    }

    // Resolve every identifier reference once.  OXC stores the symbol identity
    // on `Reference`, while AST IdentifierReference only carries a ReferenceId;
    // the span map lets all nine handlers use the same identity proof.
    let reference_symbols = reference_symbols(semantic);
    let mut out = Vec::new();

    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::ImportDeclaration(import) => {
                collect_s1128(ctx, semantic, &targets, import, &mut out);
            }
            AstKind::Function(function) => {
                collect_s1172(semantic, &targets, function, &mut out);
                collect_s4322(
                    ctx,
                    semantic,
                    &targets,
                    function,
                    &reference_symbols,
                    &mut out,
                );
                collect_s6759(ctx, &targets, function, &mut out);
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                collect_s1172_arrow(semantic, &targets, arrow, &mut out);
            }
            AstKind::PropertyDefinition(property) => {
                collect_s1444(ctx, &targets, property, &mut out);
            }
            AstKind::CallExpression(call) => {
                collect_s2871(ctx, semantic, &targets, call, &reference_symbols, &mut out);
                collect_s3415(ctx, &targets, call, &mut out);
                collect_s4043(ctx, semantic, &targets, call, &reference_symbols, &mut out);
            }
            AstKind::StaticMemberExpression(member) => {
                collect_s2990(ctx, semantic, &targets, member, &mut out);
            }
            _ => {}
        }
    }
    // A malformed/recovered tree can expose the same issue through more than
    // one node.  Keep the first AST-proven candidate per issue/action while
    // preserving distinct alternatives (S2990 has two).
    out.sort_by_key(|(index, _)| *index);
    let mut seen = HashSet::new();
    out.retain(|(index, candidate)| seen.insert((*index, candidate.id)));
    out
}

fn issue_span(ctx: &AnalysisContext<'_>, issue: &Issue) -> Option<Span> {
    if issue.range.start.line == 0 || issue.range.end.line == 0 {
        return None;
    }
    Some(Span::new(
        u32::try_from(position_offset(ctx, issue.range.start)?).ok()?,
        u32::try_from(position_offset(ctx, issue.range.end)?).ok()?,
    ))
}

fn position_offset(ctx: &AnalysisContext<'_>, pos: hoonarqube_ir::Pos) -> Option<usize> {
    let line = usize::try_from(pos.line).ok()?.checked_sub(1)?;
    let line_start = *ctx.index.line_starts.get(line)? as usize;
    let rest = ctx.source.get(line_start..)?;
    let column = usize::try_from(pos.column).ok()?;
    Some(rest.char_indices().nth(column).map_or_else(
        || line_start + rest.len(),
        |(offset, _)| line_start + offset,
    ))
}

fn reference_symbols(semantic: &Semantic<'_>) -> HashMap<(u32, u32), SymbolId> {
    let mut references = HashMap::new();
    for symbol in semantic.scoping().symbol_ids() {
        for reference in semantic.symbol_references(symbol) {
            let span = semantic.reference_span(reference);
            references.insert((span.start, span.end), symbol);
        }
    }
    references
}

fn target_indices<'a>(
    targets: &'a [Target],
    rule: &'a str,
    span: Span,
) -> impl Iterator<Item = usize> + 'a {
    targets
        .iter()
        .filter(move |target| target.rule == rule && target.span == span)
        .map(|target| target.index)
}

fn emit(
    targets: &[Target],
    out: &mut Vec<(usize, Candidate)>,
    rule: &str,
    span: Span,
    id: &'static str,
    message: &'static str,
    edits: &[(usize, usize, String)],
) {
    for index in target_indices(targets, rule, span) {
        out.push((index, candidate(id, message, edits.iter().cloned())));
    }
}

fn source_text<'a>(ctx: &'a AnalysisContext<'_>, span: Span) -> Option<&'a str> {
    ctx.source.get(span.start as usize..span.end as usize)
}
fn is_jsx_pragma_binding(ctx: &AnalysisContext<'_>, name: &str) -> bool {
    let pragma = format!("@jsx {name}");
    ctx.comments.iter().any(|comment| {
        ctx.source
            .get(comment.body.start as usize..comment.body.end as usize)
            .is_some_and(|body| body.contains(&pragma))
    })
}

fn has_read_reference(semantic: &Semantic<'_>, symbol: SymbolId) -> bool {
    semantic
        .symbol_references(symbol)
        .any(|reference| reference.flags().contains(ReferenceFlags::Read))
}

fn import_side_effect_free(ctx: &AnalysisContext<'_>, import: &ImportDeclaration<'_>) -> bool {
    ctx.semantic_facts
        .and_then(|facts| {
            facts.imports.iter().find(|fact| {
                fact.kind == "import"
                    && fact.span.start == import.span.start
                    && fact.span.end == import.span.end
            })
        })
        .and_then(|fact| fact.side_effect_free)
        == Some(true)
}
fn collect_s1128(
    ctx: &AnalysisContext<'_>,
    semantic: &Semantic<'_>,
    targets: &[Target],
    import: &ImportDeclaration<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    let Some(specifiers) = import.specifiers.as_ref() else {
        return;
    };
    for specifier in specifiers {
        collect_s1128_specifier(ctx, semantic, targets, import, specifiers, specifier, out);
    }
}

fn collect_s1128_specifier(
    ctx: &AnalysisContext<'_>,
    semantic: &Semantic<'_>,
    targets: &[Target],
    import: &ImportDeclaration<'_>,
    specifiers: &[ImportDeclarationSpecifier<'_>],
    specifier: &ImportDeclarationSpecifier<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    let local = match specifier {
        ImportDeclarationSpecifier::ImportSpecifier(specifier) => &specifier.local,
        ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => &specifier.local,
        ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => &specifier.local,
    };
    if target_indices(targets, "S1128", local.span)
        .next()
        .is_none()
        || local.name == "React"
        || is_jsx_pragma_binding(ctx, local.name.as_str())
    {
        return;
    }
    let Some(symbol) = local.symbol_id.get() else {
        return;
    };
    if has_read_reference(semantic, symbol)
        || semantic
            .symbol_references(symbol)
            .any(|reference| reference.flags().is_write())
    {
        return;
    }
    if specifiers.len() == 1 {
        collect_s1128_single(ctx, targets, import, specifier, local.span, out);
        return;
    }
    let Some(edit) = s1128_multi_edit(ctx, import, specifiers, specifier) else {
        return;
    };
    emit(
        targets,
        out,
        "S1128",
        local.span,
        "s1128-remove-import-variable",
        "Remove this unused import",
        &[edit],
    );
}
fn collect_s1128_single(
    ctx: &AnalysisContext<'_>,
    targets: &[Target],
    import: &ImportDeclaration<'_>,
    specifier: &ImportDeclarationSpecifier<'_>,
    local_span: Span,
    out: &mut Vec<(usize, Candidate)>,
) {
    let specifier_is_type = matches!(
        specifier,
        ImportDeclarationSpecifier::ImportSpecifier(specifier)
            if specifier.import_kind.is_type()
    );
    let edit = if import.import_kind.is_type() || specifier_is_type {
        (
            import.span.start as usize,
            import.span.end as usize,
            String::new(),
        )
    } else {
        // Preserve module evaluation and every import attribute.
        (
            import.span.start as usize,
            import.source.span.start as usize,
            "import ".to_owned(),
        )
    };
    emit(
        targets,
        out,
        "S1128",
        local_span,
        "s1128-remove-import-variable",
        "Remove this unused import",
        &[edit],
    );
    // Removing a value import also removes module evaluation.  Offer that
    // alternative only when the project helper proved the dependency pure;
    // unknown or effectful modules retain the safe side-effect import.
    if !import.import_kind.is_type() && !specifier_is_type && import_side_effect_free(ctx, import) {
        emit(
            targets,
            out,
            "S1128",
            local_span,
            "s1128-remove-import-statement",
            "Remove this import statement",
            &[(
                import.span.start as usize,
                import.span.end as usize,
                String::new(),
            )],
        );
    }
}

fn s1128_multi_edit(
    ctx: &AnalysisContext<'_>,
    import: &ImportDeclaration<'_>,
    specifiers: &[ImportDeclarationSpecifier<'_>],
    specifier: &ImportDeclarationSpecifier<'_>,
) -> Option<(usize, usize, String)> {
    match specifier {
        ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => {
            default_import_edit(ctx, default, specifiers)
        }
        ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => {
            namespace_import_edit(namespace, specifiers)
        }
        ImportDeclarationSpecifier::ImportSpecifier(named) => {
            named_import_edit(ctx, import, named, specifiers)
        }
    }
}

fn default_import_edit(
    ctx: &AnalysisContext<'_>,
    default: &ImportDefaultSpecifier<'_>,
    specifiers: &[ImportDeclarationSpecifier<'_>],
) -> Option<(usize, usize, String)> {
    if let Some(first_named) = specifiers
        .iter()
        .find(|specifier| matches!(specifier, ImportDeclarationSpecifier::ImportSpecifier(_)))
    {
        // Keep the named braces; remove through their opening brace so
        // `import d, { x }` becomes `import { x }`.
        let open = ctx.tokens.iter().find(|token| {
            token.kind() == Kind::LCurly
                && token.start() >= default.span.end
                && token.end() <= specifier_span(first_named).start
        })?;
        Some((
            default.span.start as usize,
            open.start() as usize,
            String::new(),
        ))
    } else {
        specifiers
            .iter()
            .find_map(|specifier| match specifier {
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => Some(namespace),
                _ => None,
            })
            .map(|namespace| {
                // `import d, * as ns` becomes `import * as ns`.
                (
                    default.span.start as usize,
                    namespace.span.start as usize,
                    String::new(),
                )
            })
    }
}

fn namespace_import_edit(
    namespace: &ImportNamespaceSpecifier<'_>,
    specifiers: &[ImportDeclarationSpecifier<'_>],
) -> Option<(usize, usize, String)> {
    let default = specifiers.iter().find_map(|specifier| match specifier {
        ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => Some(default),
        _ => None,
    })?;
    Some((
        default.span.end as usize,
        namespace.span.end as usize,
        String::new(),
    ))
}

fn named_import_edit(
    ctx: &AnalysisContext<'_>,
    import: &ImportDeclaration<'_>,
    named: &ImportSpecifier<'_>,
    specifiers: &[ImportDeclarationSpecifier<'_>],
) -> Option<(usize, usize, String)> {
    let named_specifiers = specifiers
        .iter()
        .filter_map(|specifier| match specifier {
            ImportDeclarationSpecifier::ImportSpecifier(named) => Some(named),
            _ => None,
        })
        .collect::<Vec<_>>();
    let named_index = named_specifiers
        .iter()
        .position(|candidate| candidate.span == named.span)?;
    if named_specifiers.len() == 1 {
        // With a default import, remove the complete named clause while
        // leaving `import default from ...` valid.
        let default = specifiers.iter().find_map(|specifier| match specifier {
            ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => Some(default),
            _ => None,
        })?;
        let close = ctx.tokens.iter().find(|token| {
            token.kind() == Kind::RCurly
                && token.start() >= named.span.end
                && token.end() <= import.source.span.start
        })?;
        Some((
            default.span.end as usize,
            close.end() as usize,
            String::new(),
        ))
    } else if named_index == 0 {
        Some((
            named.span.start as usize,
            named_specifiers[1].span.start as usize,
            String::new(),
        ))
    } else {
        Some((
            named_specifiers[named_index - 1].span.end as usize,
            named.span.end as usize,
            String::new(),
        ))
    }
}

fn specifier_span(specifier: &ImportDeclarationSpecifier<'_>) -> Span {
    match specifier {
        ImportDeclarationSpecifier::ImportSpecifier(specifier) => specifier.span,
        ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => specifier.span,
        ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => specifier.span,
    }
}

fn collect_s1172(
    semantic: &Semantic<'_>,
    targets: &[Target],
    function: &Function<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    collect_s1172_parameters(
        semantic,
        targets,
        &function.params,
        function
            .this_param
            .as_ref()
            .map(|parameter| parameter.span.end),
        function.node_id.get(),
        out,
    );
}

fn collect_s1172_arrow(
    semantic: &Semantic<'_>,
    targets: &[Target],
    arrow: &ArrowFunctionExpression<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    collect_s1172_parameters(
        semantic,
        targets,
        &arrow.params,
        None,
        arrow.node_id.get(),
        out,
    );
}

fn collect_s1172_parameters(
    semantic: &Semantic<'_>,
    targets: &[Target],
    params: &FormalParameters<'_>,
    this_param_end: Option<u32>,
    function_node: oxc_syntax::node::NodeId,
    out: &mut Vec<(usize, Candidate)>,
) {
    if setter_or_arguments_sensitive(semantic, function_node) {
        return;
    }
    for (index, parameter) in params.items.iter().enumerate() {
        collect_s1172_parameter(
            semantic,
            targets,
            params,
            this_param_end,
            index,
            parameter,
            out,
        );
    }
    if let Some(rest) = params.rest.as_ref() {
        collect_s1172_rest(semantic, targets, &rest.rest.argument, out);
    }
}

fn collect_s1172_parameter(
    semantic: &Semantic<'_>,
    targets: &[Target],
    params: &FormalParameters<'_>,
    this_param_end: Option<u32>,
    index: usize,
    parameter: &FormalParameter<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    if parameter.accessibility.is_some() || parameter.readonly || parameter.r#override {
        return;
    }
    let defaulted = parameter.initializer.is_some();
    let mut identifiers = Vec::new();
    binding_identifiers(&parameter.pattern, &mut identifiers);
    for identifier in identifiers {
        if !is_unused_s1172_identifier(semantic, identifier) {
            continue;
        }
        let span = identifier.span;
        emit_s1172_rename(targets, out, span);

        // SonarJS only offers removal for a direct parameter identifier;
        // destructured/defaulted parameters retain their binding shape.
        if defaulted || !matches!(parameter.pattern, BindingPattern::BindingIdentifier(_)) {
            continue;
        }
        let Some(remove) = parameter_removal_edit(params, index, this_param_end) else {
            continue;
        };
        emit(
            targets,
            out,
            "S1172",
            span,
            "s1172-remove-parameter",
            "Remove the unused parameter (beware of call sites)",
            &[remove],
        );
    }
}

fn collect_s1172_rest(
    semantic: &Semantic<'_>,
    targets: &[Target],
    pattern: &BindingPattern<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    let mut identifiers = Vec::new();
    binding_identifiers(pattern, &mut identifiers);
    for identifier in identifiers {
        if is_unused_s1172_identifier(semantic, identifier) {
            emit_s1172_rename(targets, out, identifier.span);
        }
    }
}

fn is_unused_s1172_identifier(semantic: &Semantic<'_>, identifier: &BindingIdentifier<'_>) -> bool {
    if identifier.name.starts_with('_') || is_shorthand_binding(semantic, identifier.node_id.get())
    {
        return false;
    }
    let Some(symbol) = identifier.symbol_id.get() else {
        return false;
    };
    // A default expression can itself reference the parameter.  Do
    // not rename in that case; otherwise the initializer changes.
    semantic.symbol_references(symbol).next().is_none()
}

fn emit_s1172_rename(targets: &[Target], out: &mut Vec<(usize, Candidate)>, span: Span) {
    let rename = [(span.start as usize, span.start as usize, "_".to_owned())];
    emit(
        targets,
        out,
        "S1172",
        span,
        "s1172-rename-parameter",
        "Rename the unused parameter",
        &rename,
    );
}
fn binding_identifiers<'a>(
    pattern: &'a BindingPattern<'a>,
    out: &mut Vec<&'a BindingIdentifier<'a>>,
) {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => out.push(identifier),
        BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                binding_identifiers(&property.value, out);
            }
            if let Some(rest) = object.rest.as_ref() {
                binding_identifiers(&rest.argument, out);
            }
        }
        BindingPattern::ArrayPattern(array) => {
            for element in &array.elements {
                if let Some(element) = element.as_ref() {
                    binding_identifiers(element, out);
                }
            }
            if let Some(rest) = array.rest.as_ref() {
                binding_identifiers(&rest.argument, out);
            }
        }
        BindingPattern::AssignmentPattern(assignment) => {
            binding_identifiers(&assignment.left, out);
        }
    }
}
fn is_shorthand_binding(semantic: &Semantic<'_>, node_id: oxc_syntax::node::NodeId) -> bool {
    semantic
        .nodes()
        .ancestor_kinds(node_id)
        .any(|kind| matches!(kind, AstKind::BindingProperty(property) if property.shorthand))
}

fn setter_or_arguments_sensitive(
    semantic: &Semantic<'_>,
    node_id: oxc_syntax::node::NodeId,
) -> bool {
    for kind in semantic.nodes().ancestor_kinds(node_id) {
        match kind {
            AstKind::MethodDefinition(method) if method.kind == MethodDefinitionKind::Set => {
                return true;
            }
            AstKind::ObjectProperty(property) if property.kind == PropertyKind::Set => {
                return true;
            }
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                break;
            }
            _ => {}
        }
    }
    semantic.nodes().iter().any(|node| {
        let AstKind::IdentifierReference(reference) = node.kind() else {
            return false;
        };
        if reference.name != "arguments"
            || !is_nearest_function(semantic, reference.node_id.get(), node_id)
        {
            return false;
        }
        semantic.is_reference_to_global_variable(reference)
    })
}

fn is_nearest_function(
    semantic: &Semantic<'_>,
    reference_id: oxc_syntax::node::NodeId,
    function_id: oxc_syntax::node::NodeId,
) -> bool {
    semantic
        .nodes()
        .ancestor_ids(reference_id)
        .find_map(|ancestor| match semantic.nodes().kind(ancestor) {
            // Arrow functions capture the nearest ordinary function's
            // `arguments` binding.
            AstKind::Function(function) => Some(function.node_id.get() == function_id),
            _ => None,
        })
        .unwrap_or(false)
}
fn parameter_removal_edit(
    params: &FormalParameters<'_>,
    index: usize,
    this_param_end: Option<u32>,
) -> Option<(usize, usize, String)> {
    if params.items.len() == 1 && params.rest.is_none() {
        let parameter = params.items.first()?;
        if let Some(this_end) = this_param_end {
            return Some((
                this_end as usize,
                parameter.span.end as usize,
                String::new(),
            ));
        }
        return Some((
            params.span.start as usize,
            params.span.end as usize,
            "()".to_owned(),
        ));
    }
    let parameter = params.items.get(index)?;
    if index == 0 {
        let end = if let Some(next) = params.items.get(index + 1) {
            next.span.start
        } else if let Some(rest) = params.rest.as_ref() {
            rest.span.start
        } else {
            parameter.span.end
        };
        Some((parameter.span.start as usize, end as usize, String::new()))
    } else {
        let start = params.items[index - 1].span.end;
        Some((start as usize, parameter.span.end as usize, String::new()))
    }
}

fn collect_s1444(
    ctx: &AnalysisContext<'_>,
    targets: &[Target],
    property: &PropertyDefinition<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    if !property.r#static
        || property.readonly
        || matches!(
            property.accessibility,
            Some(TSAccessibility::Private | TSAccessibility::Protected)
        )
    {
        return;
    }
    let Some(static_token) = ctx.tokens.iter().find(|token| {
        token.kind() == Kind::Static
            && token.start() >= property.span.start
            && token.end() <= property.span.end
    }) else {
        return;
    };
    let edit = (
        static_token.end() as usize,
        static_token.end() as usize,
        " readonly".to_owned(),
    );
    emit(
        targets,
        out,
        "S1444",
        property.span,
        "s1444-add-readonly",
        "Add \"readonly\" keyword",
        &[edit],
    );
}

fn collect_s2871(
    ctx: &AnalysisContext<'_>,
    semantic: &Semantic<'_>,
    targets: &[Target],
    call: &CallExpression<'_>,
    reference_symbols: &HashMap<(u32, u32), SymbolId>,
    out: &mut Vec<(usize, Candidate)>,
) {
    if !call.arguments.is_empty() {
        return;
    }
    let (object, target_span, method) = match &call.callee {
        Expression::StaticMemberExpression(member) => (
            &member.object,
            member.property.span(),
            member.property.name.as_str(),
        ),
        Expression::ComputedMemberExpression(member) => {
            let Expression::StringLiteral(property) = &member.expression else {
                return;
            };
            (&member.object, member.span(), property.value.as_str())
        }
        _ => return,
    };
    if !matches!(
        method,
        "sort" | "\"sort\"" | "'sort'" | "toSorted" | "\"toSorted\"" | "'toSorted'"
    ) {
        return;
    }
    let Some(kind) = proven_array_type(semantic, object, reference_symbols) else {
        return;
    };
    let (comparator, id, message) = match kind {
        ArrayKind::Number => (
            "(a, b) => (a - b)",
            "s2871-suggest-numeric-order",
            "Add a comparator function to sort in ascending order",
        ),
        ArrayKind::String => (
            "(a, b) => a.localeCompare(b)",
            "s2871-suggest-language-sensitive-order",
            "Add a comparator function to sort in ascending language-sensitive order",
        ),
        ArrayKind::BigInt => (
            "(a, b) => {\n  if (a < b) {\n    return -1;\n  } else if (a > b) {\n    return 1;\n  } else {\n    return 0;\n  }\n}",
            "s2871-suggest-numeric-order",
            "Add a comparator function to sort in ascending order",
        ),
        ArrayKind::Any => return,
    };
    let Some(close) = closing_paren(ctx.tokens, call.span) else {
        return;
    };
    let edit = (
        close.start() as usize,
        close.start() as usize,
        comparator.to_owned(),
    );
    emit(targets, out, "S2871", target_span, id, message, &[edit]);
}

fn collect_s2990(
    _ctx: &AnalysisContext<'_>,
    semantic: &Semantic<'_>,
    targets: &[Target],
    member: &StaticMemberExpression<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    let Expression::ThisExpression(this_expression) = &member.object else {
        return;
    };
    if target_indices(targets, "S2990", this_expression.span)
        .next()
        .is_none()
    {
        return;
    }
    // `this` inside a class is receiver-bound even in a static field/block.
    // Arrow functions do not create a new `this`; ordinary functions do.
    if semantic
        .nodes()
        .ancestor_kinds(this_expression.node_id.get())
        .any(|kind| {
            matches!(
                kind,
                AstKind::Class(_) | AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        })
    {
        return;
    }
    let property = member.property.name.as_str();
    let remove = [(
        this_expression.span.start as usize,
        member.span.end as usize,
        property.to_owned(),
    )];
    emit(
        targets,
        out,
        "S2990",
        this_expression.span,
        "s2990-remove-this",
        "Remove \"this\"",
        &remove,
    );
    let window = [(
        this_expression.span.start as usize,
        this_expression.span.end as usize,
        "window".to_owned(),
    )];
    emit(
        targets,
        out,
        "S2990",
        this_expression.span,
        "s2990-use-window",
        "Replace \"this\" with \"window\" object",
        &window,
    );
}

fn collect_s3415(
    ctx: &AnalysisContext<'_>,
    targets: &[Target],
    call: &CallExpression<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    let Some((actual, expected)) = assertion_arguments(call) else {
        return;
    };
    if !crate::rules::shared::is_literal_expression(actual)
        || crate::rules::shared::is_literal_expression(expected)
    {
        return;
    }
    let Some(actual_text) = source_text(ctx, actual.span()) else {
        return;
    };
    let Some(expected_text) = source_text(ctx, expected.span()) else {
        return;
    };
    let edits = [
        (
            actual.span().start as usize,
            actual.span().end as usize,
            expected_text.to_owned(),
        ),
        (
            expected.span().start as usize,
            expected.span().end as usize,
            actual_text.to_owned(),
        ),
    ];

    emit(
        targets,
        out,
        "S3415",
        call.span,
        "s3415-swap-arguments",
        "Swap arguments",
        &edits,
    );
}

fn is_assert_receiver(expression: &Expression<'_>, expected: &str) -> bool {
    matches!(
        expression,
        Expression::Identifier(identifier) if identifier.name == expected
    )
}

fn argument_expression<'r, 'a>(argument: &'r Argument<'a>) -> Option<&'r Expression<'a>> {
    argument.as_expression()
}

fn assertion_arguments<'a>(
    call: &'a CallExpression<'a>,
) -> Option<(&'a Expression<'a>, &'a Expression<'a>)> {
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return None;
    };
    let property = member.property.name.as_str();
    if is_assert_receiver(&member.object, "assert")
        && matches!(
            property,
            "equal"
                | "notEqual"
                | "strictEqual"
                | "notStrictEqual"
                | "deepEqual"
                | "notDeepEqual"
                | "closeTo"
                | "approximately"
                | "fail"
        )
        && call.arguments.len() > 1
    {
        return Some((
            argument_expression(call.arguments.first()?)?,
            argument_expression(call.arguments.get(1)?)?,
        ));
    }
    if property == "fail"
        && (is_assert_receiver(&member.object, "expect")
            || is_assert_receiver(&member.object, "should"))
        && call.arguments.len() > 1
    {
        return Some((
            argument_expression(call.arguments.first()?)?,
            argument_expression(call.arguments.get(1)?)?,
        ));
    }
    if matches!(property, "equal" | "eql" | "closeTo") && call.arguments.len() == 1 {
        let expected = argument_expression(call.arguments.first()?)?;
        let mut root = &member.object;
        while let Expression::StaticMemberExpression(chain) = root {
            root = &chain.object;
        }
        let Expression::CallExpression(expect_call) = root else {
            return None;
        };
        let Expression::Identifier(identifier) = &expect_call.callee else {
            return None;
        };
        if identifier.name != "expect" || expect_call.arguments.len() != 1 {
            return None;
        }
        let actual = argument_expression(expect_call.arguments.first()?)?;
        return Some((actual, expected));
    }
    None
}

fn collect_s4043(
    ctx: &AnalysisContext<'_>,
    semantic: &Semantic<'_>,
    targets: &[Target],
    call: &CallExpression<'_>,
    reference_symbols: &HashMap<(u32, u32), SymbolId>,
    out: &mut Vec<(usize, Candidate)>,
) {
    let (object, property_span, method_text) = match &call.callee {
        Expression::StaticMemberExpression(member) => (
            &member.object,
            member.property.span(),
            member.property.name.as_str(),
        ),
        Expression::ComputedMemberExpression(member) => {
            let Expression::StringLiteral(property) = &member.expression else {
                return;
            };
            (&member.object, property.span, property.value.as_str())
        }
        _ => return,
    };
    let suggested_method = match method_text {
        "sort" | "\"sort\"" | "'sort'" => "toSorted",
        "reverse" | "\"reverse\"" | "'reverse'" => "toReversed",
        _ => return,
    };
    if !proven_array_identity(semantic, object, reference_symbols) {
        return;
    }
    let Some(property_text) = source_text(ctx, property_span) else {
        return;
    };
    let replacement = if property_text.starts_with('"') && property_text.ends_with('"') {
        format!("\"{suggested_method}\"")
    } else if property_text.starts_with('\'') && property_text.ends_with('\'') {
        format!("'{suggested_method}'")
    } else {
        suggested_method.to_owned()
    };
    let edit = (
        property_span.start as usize,
        property_span.end as usize,
        replacement,
    );
    emit(
        targets,
        out,
        "S4043",
        call.span,
        "s4043-suggest-method",
        "Replace with the non-mutating method",
        &[edit],
    );
}

fn collect_s4322(
    ctx: &AnalysisContext<'_>,
    semantic: &Semantic<'_>,
    targets: &[Target],
    function: &Function<'_>,
    reference_symbols: &HashMap<(u32, u32), SymbolId>,
    out: &mut Vec<(usize, Candidate)>,
) {
    if function.this_param.is_some() {
        return;
    }
    if let Some(return_type) = function.return_type.as_ref()
        && !matches!(return_type.type_annotation, TSType::TSBooleanKeyword(_))
    {
        return;
    }
    let declaration_kind = function.r#type == FunctionType::FunctionDeclaration;
    let method_kind = semantic
        .nodes()
        .ancestor_kinds(function.node_id.get())
        .find_map(|kind| match kind {
            AstKind::MethodDefinition(method) => Some(method.kind),
            _ => None,
        });
    if !declaration_kind && method_kind != Some(MethodDefinitionKind::Method) {
        return;
    }
    let Some(body) = function.body.as_deref() else {
        return;
    };
    let [Statement::ReturnStatement(return_statement)] = body.statements.as_slice() else {
        return;
    };
    let Some(argument) = return_statement.argument.as_ref() else {
        return;
    };
    let Some((cast_expression, cast_type)) = guarded_cast(argument) else {
        return;
    };
    if matches!(cast_type, TSType::TSAnyKeyword(_)) {
        return;
    }
    let parameter_symbol = if function.params.items.len() == 1 && function.params.rest.is_none() {
        match &function.params.items[0].pattern {
            BindingPattern::BindingIdentifier(identifier) => identifier.symbol_id.get(),
            _ => None,
        }
    } else {
        None
    };
    let Some(parameter_symbol) = parameter_symbol else {
        return;
    };
    let cast_base = strip_parentheses(cast_expression);
    let Expression::Identifier(cast_base_identifier) = cast_base else {
        return;
    };
    let Some(cast_base_text) = source_text(ctx, cast_base.span()) else {
        return;
    };
    let Some(cast_type_text) = source_text(ctx, cast_type.span()) else {
        return;
    };
    if reference_symbols
        .get(&(
            cast_base_identifier.span.start,
            cast_base_identifier.span.end,
        ))
        .is_none_or(|symbol| *symbol != parameter_symbol)
    {
        return;
    }
    let issue_span = function
        .return_type
        .as_ref()
        .map(|return_type| return_type.span)
        .or_else(|| function.id.as_ref().map(|id| id.span));
    let Some(issue_span) = issue_span else {
        return;
    };
    let predicate = format!(": {cast_base_text} is {cast_type_text}");
    let (edit_start, edit_end) = if let Some(return_type) = function.return_type.as_ref() {
        (return_type.span.start, return_type.span.end)
    } else {
        let Some(close) = closing_paren(ctx.tokens, function.params.span) else {
            return;
        };
        let insertion = close.end();
        (insertion, insertion)
    };
    let edit = (edit_start as usize, edit_end as usize, predicate);
    emit(
        targets,
        out,
        "S4322",
        issue_span,
        "s4322-use-type-predicate",
        "Use type predicate",
        &[edit],
    );
}

fn guarded_cast<'a>(
    expression: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, &'a TSType<'a>)> {
    let expression = strip_parentheses(expression);
    match expression {
        Expression::BinaryExpression(binary)
            if matches!(
                binary.operator,
                BinaryOperator::Inequality | BinaryOperator::StrictInequality
            ) =>
        {
            if is_undefined(&binary.right) {
                cast_from_member(&binary.left)
            } else if is_undefined(&binary.left) {
                cast_from_member(&binary.right)
            } else {
                None
            }
        }
        Expression::CallExpression(call) if call.arguments.len() == 1 => {
            let Expression::Identifier(identifier) = &call.callee else {
                return None;
            };
            if identifier.name != "Boolean" {
                return None;
            }
            argument_expression(call.arguments.first()?).and_then(cast_from_member)
        }
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => {
            let Expression::UnaryExpression(inner) = &unary.argument else {
                return None;
            };
            if inner.operator != UnaryOperator::LogicalNot {
                return None;
            }
            cast_from_member(&inner.argument)
        }
        _ => None,
    }
}

fn is_undefined(expression: &Expression<'_>) -> bool {
    match strip_parentheses(expression) {
        Expression::Identifier(identifier) => identifier.name == "undefined",
        _ => false,
    }
}

fn cast_from_member<'a>(
    expression: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, &'a TSType<'a>)> {
    let member_object = match strip_parentheses(expression) {
        Expression::StaticMemberExpression(member) => &member.object,
        Expression::ComputedMemberExpression(member) => &member.object,
        _ => return None,
    };
    match strip_parentheses(member_object) {
        Expression::TSAsExpression(cast) => Some((&cast.expression, &cast.type_annotation)),
        Expression::TSTypeAssertion(cast) => Some((&cast.expression, &cast.type_annotation)),
        _ => None,
    }
}

fn strip_parentheses<'a>(expression: &'a Expression<'a>) -> &'a Expression<'a> {
    match expression {
        Expression::ParenthesizedExpression(parenthesized) => {
            strip_parentheses(&parenthesized.expression)
        }
        _ => expression,
    }
}

fn collect_s6759(
    ctx: &AnalysisContext<'_>,
    targets: &[Target],
    function: &Function<'_>,
    out: &mut Vec<(usize, Candidate)>,
) {
    if function.r#type != FunctionType::FunctionDeclaration
        || !function
            .id
            .as_ref()
            .is_some_and(|id| id.name.starts_with(|ch: char| ch.is_ascii_uppercase()))
        || function.params.items.len() > 1
    {
        return;
    }
    let Some(parameter) = function.params.items.first() else {
        return;
    };
    let Some(annotation) = parameter.type_annotation.as_ref() else {
        return;
    };
    let Some(old_text) = source_text(ctx, annotation.type_annotation.span()) else {
        return;
    };
    let edit = (
        annotation.type_annotation.span().start as usize,
        annotation.type_annotation.span().end as usize,
        format!("Readonly<{old_text}>"),
    );
    emit(
        targets,
        out,
        "S6759",
        parameter.span,
        "s6759-mark-props-readonly",
        "Mark the props as read-only",
        &[edit],
    );
}

fn closing_paren(tokens: &[Token], span: Span) -> Option<&Token> {
    tokens.iter().rfind(|token| {
        token.kind() == Kind::RParen && token.start() >= span.start && token.end() <= span.end
    })
}

fn proven_array_identity(
    semantic: &Semantic<'_>,
    expression: &Expression<'_>,
    reference_symbols: &HashMap<(u32, u32), SymbolId>,
) -> bool {
    match expression {
        Expression::ParenthesizedExpression(parenthesized) => {
            proven_array_identity(semantic, &parenthesized.expression, reference_symbols)
        }
        Expression::ArrayExpression(_) => true,
        Expression::Identifier(identifier) => reference_symbols
            .get(&(identifier.span.start, identifier.span.end))
            .is_some_and(|symbol| proven_symbol_array_identity(semantic, *symbol)),
        _ => false,
    }
}

fn proven_symbol_array_identity(semantic: &Semantic<'_>, symbol: SymbolId) -> bool {
    let declaration_node = semantic.symbol_declaration(symbol);
    for node in
        std::iter::once(declaration_node).chain(semantic.nodes().ancestors(declaration_node.id()))
    {
        match node.kind() {
            AstKind::VariableDeclarator(declarator) => {
                let direct_binding = matches!(
                    &declarator.id,
                    BindingPattern::BindingIdentifier(identifier)
                        if identifier.symbol_id.get() == Some(symbol)
                );
                if !direct_binding {
                    return false;
                }
                let const_array = declarator.type_annotation.is_none()
                    && is_const_variable(semantic, declaration_node.id())
                    && declarator
                        .init
                        .as_ref()
                        .is_some_and(|init| matches!(init, Expression::ArrayExpression(_)));
                return const_array
                    && !semantic
                        .symbol_references(symbol)
                        .any(|reference| reference.flags().is_write());
            }
            AstKind::FormalParameter(_) | AstKind::FormalParameterRest(_) => return false,
            _ => {}
        }
    }
    false
}

fn is_const_variable(semantic: &Semantic<'_>, declaration_id: oxc_syntax::node::NodeId) -> bool {
    semantic
        .nodes()
        .ancestors(declaration_id)
        .find_map(|node| match node.kind() {
            AstKind::VariableDeclaration(declaration) => {
                Some(declaration.kind == VariableDeclarationKind::Const)
            }
            _ => None,
        })
        .unwrap_or(false)
}

fn proven_array_type(
    semantic: &Semantic<'_>,
    expression: &Expression<'_>,
    reference_symbols: &HashMap<(u32, u32), SymbolId>,
) -> Option<ArrayKind> {
    match expression {
        Expression::ParenthesizedExpression(parenthesized) => {
            proven_array_type(semantic, &parenthesized.expression, reference_symbols)
        }
        Expression::ArrayExpression(array) => array_literal_kind(array),
        Expression::Identifier(identifier) => {
            let symbol = reference_symbols.get(&(identifier.span.start, identifier.span.end))?;
            proven_symbol_type(semantic, *symbol)
        }
        _ => None,
    }
}

fn array_literal_kind(array: &ArrayExpression<'_>) -> Option<ArrayKind> {
    let mut kind = None;
    for element in &array.elements {
        let expression = element.as_expression()?;
        let next = match expression {
            Expression::NumericLiteral(_) => ArrayKind::Number,
            Expression::StringLiteral(_) => ArrayKind::String,
            Expression::BigIntLiteral(_) => ArrayKind::BigInt,
            _ => return None,
        };
        if let Some(previous) = kind
            && previous != next
        {
            return None;
        }
        kind = Some(next);
    }
    kind
}

fn proven_symbol_type(semantic: &Semantic<'_>, symbol: SymbolId) -> Option<ArrayKind> {
    let declaration_node = semantic.symbol_declaration(symbol);
    for node in
        std::iter::once(declaration_node).chain(semantic.nodes().ancestors(declaration_node.id()))
    {
        match node.kind() {
            AstKind::VariableDeclarator(declarator) => {
                return proven_variable_type(semantic, symbol, declaration_node.id(), declarator);
            }
            AstKind::FormalParameter(parameter) => {
                return proven_typed_binding_type(
                    &parameter.pattern,
                    parameter.type_annotation.as_deref(),
                    symbol,
                );
            }
            AstKind::FormalParameterRest(parameter) => {
                return proven_typed_binding_type(
                    &parameter.rest.argument,
                    parameter.type_annotation.as_deref(),
                    symbol,
                );
            }
            _ => {}
        }
    }
    None
}

fn proven_variable_type(
    semantic: &Semantic<'_>,
    symbol: SymbolId,
    declaration_id: oxc_syntax::node::NodeId,
    declarator: &VariableDeclarator<'_>,
) -> Option<ArrayKind> {
    if !binding_matches_symbol(&declarator.id, symbol) {
        return None;
    }
    if let Some(annotation) = declarator.type_annotation.as_ref()
        && let Some(kind) = array_kind_from_type(&annotation.type_annotation)
    {
        return Some(kind);
    }
    if declarator.type_annotation.is_none()
        && is_const_variable(semantic, declaration_id)
        && !semantic
            .symbol_references(symbol)
            .any(|reference| reference.flags().is_write())
        && let Some(Expression::ArrayExpression(array)) = declarator.init.as_ref()
    {
        return array_literal_kind(array);
    }
    None
}

fn proven_typed_binding_type(
    pattern: &BindingPattern<'_>,
    annotation: Option<&TSTypeAnnotation<'_>>,
    symbol: SymbolId,
) -> Option<ArrayKind> {
    if !binding_matches_symbol(pattern, symbol) {
        return None;
    }
    annotation.and_then(|annotation| array_kind_from_type(&annotation.type_annotation))
}

fn binding_matches_symbol(pattern: &BindingPattern<'_>, symbol: SymbolId) -> bool {
    matches!(
        pattern,
        BindingPattern::BindingIdentifier(identifier)
            if identifier.symbol_id.get() == Some(symbol)
    )
}

fn array_kind_from_type(ty: &TSType<'_>) -> Option<ArrayKind> {
    match ty {
        TSType::TSArrayType(array) => element_kind_from_type(&array.element_type),
        TSType::TSTypeOperatorType(operator)
            if operator.operator == TSTypeOperatorOperator::Readonly =>
        {
            array_kind_from_type(&operator.type_annotation)
        }
        TSType::TSParenthesizedType(parenthesized) => {
            array_kind_from_type(&parenthesized.type_annotation)
        }
        _ => None,
    }
}

fn element_kind_from_type(ty: &TSType<'_>) -> Option<ArrayKind> {
    match ty {
        TSType::TSAnyKeyword(_) => Some(ArrayKind::Any),
        TSType::TSNumberKeyword(_) => Some(ArrayKind::Number),
        TSType::TSStringKeyword(_) => Some(ArrayKind::String),
        TSType::TSBigIntKeyword(_) => Some(ArrayKind::BigInt),
        _ => None,
    }
}
