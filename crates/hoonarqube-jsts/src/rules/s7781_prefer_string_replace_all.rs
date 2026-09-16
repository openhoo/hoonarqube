// Rule module s7781_prefer_string_replace_all (generated).
//
// `javascript:S7781` + `typescript:S7781` — Strings should use
// `replaceAll()` instead of `replace()` with a global regex. Reference
// semantics: eslint-plugin-unicorn `prefer-string-replace-all` (v65.0.1)
// wrapped by the SonarJS S7781 decorator
// (`packages/analysis/src/jsts/rules/S7781/decorator.ts`):
//
// - a non-optional `.replace(pattern, replacement)` member call with
//   exactly two arguments is reported on the `replace` property only when
//   the pattern is a global-flagged regular expression *reducible to a
//   fixed literal string* — the decorator's `getEquivalentLiteral` accepts
//   characters, single-character classes, non-capturing groups, and fixed
//   `{n}` quantifiers; capturing groups, alternations, and variable
//   quantifiers are not reducible and stay silent (so `$`-backreference
//   and function replacements, which need capture semantics, never fire);
// - `hasReducibleFlags` keeps only `g` plus the unicode-mode flags `u`/`v`;
//   `i`, `m`, `s`, `y`, `d` make the pattern non-reducible;
// - the decorator resolves the pattern through `getParsedRegex`, which
//   follows identifier references: an identifier bound to a `const`
//   regex literal or `new RegExp(literal, "…g…")` in the same file is
//   inspected like the inline form;
// - the message is the reference "Prefer `String#replaceAll()` over
//   `String#replace()`."; no auto-fix is offered.
//
// Optional calls, computed access, wrong arities, `replaceAll` (the
// upstream inverse direction), and unresolvable patterns stay silent.

use crate::context::AnalysisContext;
use crate::engine::pattern_parser::{
    ClassItem, GroupKind, PatternNode, RegexSite, constructor_regex_site, parse_regex_pattern,
    regex_site_from_literal,
};
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};

/// Entry point: `javascript:S7781` + `typescript:S7781`
/// prefer-string-replace-all check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if let Some(semantic) = ctx.semantic {
        for node in semantic.nodes().iter() {
            if let AstKind::CallExpression(call) = node.kind() {
                check_call(&mut sink, semantic, call);
            }
        }
    }
    sink.issues
}

/// The reference `create`: a `.replace(pattern, replacement)` call whose
/// pattern is a reducible global-flagged regular expression is reported on
/// the `replace` property.
fn check_call(sink: &mut IssueSink<'_>, semantic: &Semantic<'_>, call: &CallExpression<'_>) {
    let Some(property_span) = reducible_regex_replace_property(semantic, call) else {
        return;
    };
    sink.emit_span(
        RuleScope::Both,
        "S7781",
        "Prefer `String#replaceAll()` over `String#replace()`.",
        property_span,
    );
}

/// The `replace` property span when the call is a non-optional
/// two-argument member call named `replace` (the reference
/// `isMethodCall`) whose pattern is a reducible global regex, or `None`
/// otherwise.
fn reducible_regex_replace_property(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
) -> Option<Span> {
    if call.optional || call.arguments.len() != 2 {
        return None;
    }
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return None;
    };
    if member.optional || member.property.name != "replace" {
        // `replaceAll` keeps its regex pattern: the unicorn
        // "pattern can be replaced with a string literal" suggestion is a
        // different reference message without capture evidence.
        return None;
    }
    let pattern = call.arguments.first()?.as_expression()?;
    let site = resolve_regex_site(semantic, pattern)?;
    if !is_reducible_global_regex(&site) {
        return None;
    }
    Some(member.property.span())
}

/// The regex behind the pattern argument: a literal, `new RegExp` with
/// literal arguments, or an identifier bound to a `const` of either form
/// (the decorator's `getParsedRegex` identifier resolution).
fn resolve_regex_site<'a>(
    semantic: &Semantic<'a>,
    expression: &'a Expression<'a>,
) -> Option<RegexSite> {
    match unparenthesized(expression) {
        Expression::RegExpLiteral(literal) => Some(regex_site_from_literal(literal)),
        Expression::NewExpression(new_expression) => {
            let Expression::Identifier(callee) = unparenthesized(&new_expression.callee) else {
                return None;
            };
            if callee.name != "RegExp" {
                return None;
            }
            constructor_regex_site(&new_expression.arguments)
        }
        Expression::Identifier(identifier) => {
            let init = const_initializer(semantic, identifier)?;
            resolve_regex_site(semantic, init)
        }
        _ => None,
    }
}

/// The `const` initializer of a single-declaration identifier binding.
fn const_initializer<'a>(
    semantic: &Semantic<'a>,
    identifier: &oxc_ast::ast::IdentifierReference<'a>,
) -> Option<&'a Expression<'a>> {
    let symbol = identifier
        .reference_id
        .get()
        .and_then(|id| semantic.scoping().get_reference(id).symbol_id())?;
    if semantic.scoping().symbol_declarations(symbol).count() != 1 {
        return None;
    }
    let declaration = semantic.symbol_declaration(symbol);
    let AstKind::VariableDeclarator(declarator) = semantic.nodes().kind(declaration.id()) else {
        return None;
    };
    let AstKind::VariableDeclaration(kind) = semantic.nodes().parent_kind(declaration.id()) else {
        return None;
    };
    if kind.kind != oxc_ast::ast::VariableDeclarationKind::Const {
        return None;
    }
    declarator.init.as_ref()
}

/// The decorator's `hasReducibleFlags` plus `getEquivalentLiteral`: a
/// `g`-flagged regex (only `u`/`v` may join it) whose pattern reduces to a
/// non-empty fixed literal.
fn is_reducible_global_regex(site: &RegexSite) -> bool {
    // `hasReducibleFlags`: global, and no flag that changes which text the
    // pattern matches (`i`, `m`, `s`, `y`, `d`); `u`/`v` are allowed.
    if !site.has_flag('g')
        || site.has_flag('i')
        || site.has_flag('m')
        || site.has_flag('s')
        || site.has_flag('y')
        || site.has_flag('d')
    {
        return false;
    }
    let unicode_mode = site.has_flag('u') || site.has_flag('v');
    let Ok(parsed) = parse_regex_pattern(&site.pattern, unicode_mode) else {
        return false;
    };
    equivalent_literal_length(&parsed.alternatives).is_some_and(|length| length > 0)
}

/// The decorator's `getEquivalentLiteral`: the fixed literal length when
/// the pattern is exactly one alternative of fixed characters, or `None`.
fn equivalent_literal_length(alternatives: &[Vec<PatternNode>]) -> Option<usize> {
    let [alternative] = alternatives else {
        return None;
    };
    alternative.iter().try_fold(0_usize, |total, node| {
        Some(total + element_literal_length(node)?)
    })
}

/// One reducible element's literal length, or `None` when the element is
/// not a fixed character (the decorator's `reduceElement`).
fn element_literal_length(node: &PatternNode) -> Option<usize> {
    match node {
        PatternNode::Literal { .. } | PatternNode::CodeUnit { .. } => Some(1),
        PatternNode::Class {
            negated: false,
            items,
            ..
        } => match items.as_slice() {
            [ClassItem::Char { .. } | ClassItem::CodeUnit { .. }] => Some(1),
            _ => None,
        },
        PatternNode::Group {
            kind: GroupKind::NonCapturing,
            alternatives,
            ..
        } => equivalent_literal_length(alternatives),
        PatternNode::Quantified {
            node: inner,
            min,
            max: Some(max),
            ..
        } if min == max => Some(*min as usize * element_literal_length(inner)?),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7781_flags_pinned_markdown_it_replacements_anchor() {
        // Pinned anchor: markdown-it/markdown-it@3c51991
        // src/rules_core/replacements.ts:65 — `.replace(/\+-/g, '±')`.
        // Under the SonarJS decorator only the patterns reducible to a
        // fixed literal are reported; the capturing-group and `*`/`+`
        // quantifier calls stay silent.
        let source = "\
export function replace(content: string) {
  return content
    .replace(/\\+-/g, '±')
    .replace(/\\.{2,}/g, '…').replace(/([?!])…/g, '$1..')
    .replace(/([?!]){4,}/g, '$1$1$1').replace(/,{2,}/g, ',');
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7781"), 1);
        let first = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7781" && issue.range.start.line == 3)
            .expect("pinned replacements chain must be reported");
        assert_eq!(
            first.message,
            "Prefer `String#replaceAll()` over `String#replace()`."
        );
        assert_eq!(
            first.range.start.column,
            u32::try_from("    .".len()).unwrap()
        );
        assert_eq!(
            first.range.end.column,
            u32::try_from("    .".len()).unwrap() + u32::try_from("replace".len()).unwrap()
        );
    }

    #[test]
    fn s7781_flags_reducible_global_regex_patterns_only() {
        let source = "\
const a = 'x'.replace(/x/g, 'y');
const b = 'x'.replace(new RegExp('x', 'g'), 'y');
const c = 'x'.replace(/x/gu, 'y');
const d = 'x'.replace(/x/i, 'y');
const e = 'x'.replace(/x/, 'y');
const f = 'x'.replace('str', 'y');
const g = 'x'.replace(new RegExp('x'), 'y');
const h = 'x'.replaceAll(/x/g, 'y');
const i = 'x'?.replace(/x/g, 'y');
const j = 'x'['replace'](/x/g, 'y');
const k = 'x'.replace(/x/g);
";
        let keys = js_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "javascript:S7781")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![1, 2, 3]);
    }

    #[test]
    fn s7781_reports_in_both_languages() {
        let js_source = "const a = value.replace(/x/g, 'y');\n";
        let ts_source = "const a = value.replace(/x/g, 'y');\n";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7781"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7781"), 1);
    }

    #[test]
    fn s7781_resolves_const_identifier_patterns() {
        // Regression of #497: the decorator's `getParsedRegex` follows
        // identifier references to their regex initializers.
        let source = "\
const backslashRegExp = /\\\\/g;
export function normalizeSlashes(path: string): string {
    return path.includes(\"\\\\\") ? path.replace(backslashRegExp, \"/\") : path;
}
";
        let keys = ts_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "typescript:S7781")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![3]);

        // `let`-bound or multiply-declared identifiers stay unresolvable.
        let mutable = js_keys("let re = /x/g;\nconst out = 'x'.replace(re, 'y');\n");
        assert_eq!(count_key(&mutable, "javascript:S7781"), 0);
    }

    #[test]
    fn s7781_non_reducible_patterns_and_replacements_stay_silent() {
        // Regression of #498: capturing groups, alternations, and variable
        // quantifiers cannot be expressed by `replaceAll` with a literal.
        // The decorator gates on the *pattern* only — the replacement is
        // never inspected, so a function replacement still flags when the
        // pattern reduces.
        let source = "\
const a = s.replace(/(\\w ) +/g, \"$1\");
const b = s.replace(/\\s*\\/\\*+\\s*/g, \" \");
const c = s.replace(/x|y/g, 'z');
const d = s.replace(/x+/g, 'z');
const e = s.replace(/x/gi, 'z');
const f = s.replace(/x+/g, (m) => m.toUpperCase());
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7781"), 0);

        // Reducible shapes still flag: single-char class, non-capturing
        // group, fixed `{n}` quantifier — and a function replacement does
        // not suppress a reducible pattern.
        let reducible = js_keys(
            "const a = s.replace(/[x]/g, 'y');\nconst b = s.replace(/(?:ab)/g, 'y');\nconst c = s.replace(/x{2}/g, 'y');\nconst d = s.replace(/x/g, (m) => m.toUpperCase());\n",
        );
        assert_eq!(count_key(&reducible, "javascript:S7781"), 4);
    }
}
