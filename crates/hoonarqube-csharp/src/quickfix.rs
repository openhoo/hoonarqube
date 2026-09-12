//! C# IDE quick-fix planning.
//!
//! SonarAnalyzer.CSharp exposes these actions through Roslyn's
//! `CodeFixProvider`s, not through server issue metadata.  This module keeps
//! the upstream action inventory explicit and only emits a local suggestion
//! when the syntax is exact.  Actions which need symbol binding, a project
//! compilation, or a configured workspace remain gated by
//! [`QuickFixSemanticFacts`]; no same-name/type-text fallback is used.

use crate::AnalyzerOptions;
use crate::cst::{
    collect_kinds, integer_literal_natural_type, node_text, range_from_byte_offsets, range_of,
    walk_all,
};
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::{FileReport, Issue, Pos, Range, TextEdit};
use tree_sitter::{Node, Parser};

/// Whether a provider can be planned from one source file or needs the
/// compiler/workspace context used by Roslyn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Availability {
    /// The finding's exact syntax is sufficient for a lossless edit.
    Native,
    /// The edit is available only after the project context proves binding.
    ProjectSemantic,
}

/// Frozen upstream C# provider/action inventory for the #51 scope.
///
/// `actions` contains stable local action IDs.  The IDs are deliberately
/// independent of display text so clients can persist an explicit
/// `--suggestion RULE=ID` selection across wording changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Contract {
    pub(crate) key: &'static str,
    pub(crate) actions: &'static [&'static str],
    pub(crate) availability: Availability,
    pub(crate) prerequisite: &'static str,
}

pub(crate) const CSHARP_QUICKFIX_CONTRACTS: &[Contract] = &[
    Contract {
        key: "csharpsquid:S1006",
        actions: &[
            "csharp.s1006.synchronize-default",
            "csharp.s1006.remove-explicit-interface-default",
        ],
        availability: Availability::ProjectSemantic,
        prerequisite: "IParameterSymbol plus overridden/interface parameter identity; preserve two upstream actions.",
    },
    Contract {
        key: "csharpsquid:S1116",
        actions: &["csharp.s1116.remove-empty-statement"],
        availability: Availability::Native,
        prerequisite: "EmptyStatementSyntax whose parent is a block.",
    },
    Contract {
        key: "csharpsquid:S1125",
        actions: &["csharp.s1125.remove-boolean-literal"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove built-in bool equality/inequality before removing the literal and operator.",
    },
    Contract {
        key: "csharpsquid:S1128",
        actions: &["csharp.s1128.remove-unnecessary-using"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove the exact using directive is unused and removing it cannot change binding.",
    },
    Contract {
        key: "csharpsquid:S1155",
        actions: &["csharp.s1155.use-any"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove exact System.Linq Count/Any receiver and extension overload.",
    },
    Contract {
        key: "csharpsquid:S1172",
        actions: &["csharp.s1172.remove-unused-parameter"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove declared parameter identity and API-safe removal/rename across project call sites.",
    },
    Contract {
        key: "csharpsquid:S1185",
        actions: &["csharp.s1185.remove-forwarding-override"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove overridden symbol and whole-method trivia/attribute ownership.",
    },
    Contract {
        key: "csharpsquid:S1186",
        actions: &[
            "csharp.s1186.add-not-supported-throw",
            "csharp.s1186.add-empty-method-comment",
        ],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove empty method declaration and choose the distinct throw/comment action.",
    },
    Contract {
        key: "csharpsquid:S125",
        actions: &["csharp.s125.remove-commented-out-code"],
        availability: Availability::Native,
        prerequisite: "Standalone consecutive line-comment run; preserve line endings and documentation comments.",
    },
    Contract {
        key: "csharpsquid:S818",
        actions: &["csharp.s818.uppercase-literal-suffix"],
        availability: Availability::Native,
        prerequisite: "Exact lowercase numeric suffix token.",
    },
    Contract {
        key: "csharpsquid:S1451",
        actions: &["csharp.s1451.add-or-update-license-header"],
        availability: Availability::Native,
        prerequisite: "Configured literal AnalyzerOptions.header_format; empty or regular-expression mode is unsupported.",
    },
    Contract {
        key: "csharpsquid:S1858",
        actions: &["csharp.s1858.remove-redundant-tostring"],
        availability: Availability::Native,
        prerequisite: "Receiver is a syntax-proven string/interpolated-string literal and call is ToString().",
    },
    Contract {
        key: "csharpsquid:S1905",
        actions: &["csharp.s1905.remove-redundant-cast"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Compiler-proven AsExpression and Enumerable.Cast<T>/OfType<T> alternatives when complete Roslyn facts are loaded; CastExpression keeps only the separate local scalar syntax-safe IDE0004 substitute outside upstream parity.",
    },
    Contract {
        key: "csharpsquid:S1939",
        actions: &["csharp.s1939.remove-redundant-inheritance-entry"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove inherited symbol identity and comma-safe base-list edit across project.",
    },
    Contract {
        key: "csharpsquid:S1940",
        actions: &["csharp.s1940.invert-equality"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove built-in equality/inequality operator before inversion.",
    },
    Contract {
        key: "csharpsquid:S2219",
        actions: &["csharp.s2219.use-is-pattern"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove exact GetType/typeof symbols and an exact-type-safe is-pattern rewrite.",
    },
    Contract {
        key: "csharpsquid:S2290",
        actions: &["csharp.s2290.remove-virtual"],
        availability: Availability::Native,
        prerequisite: "Exact virtual modifier on a virtual field-like event finding.",
    },
    Contract {
        key: "csharpsquid:S2328",
        actions: &["csharp.s2328.remove-mutable-hash-reference"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove GetHashCode override and every referenced field's mutability/project identity.",
    },
    Contract {
        key: "csharpsquid:S2333",
        actions: &["csharp.s2333.remove-redundant-modifier"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove exact modifier/accessor and complete partial-type identity.",
    },
    Contract {
        key: "csharpsquid:S2737",
        actions: &["csharp.s2737.remove-redundant-catch"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove catch body is only a rethrow and preserve catch filters/trivia.",
    },
    Contract {
        key: "csharpsquid:S2761",
        actions: &["csharp.s2761.remove-repeated-prefix"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove built-in !/~ operator and exact nested unary expression.",
    },
    Contract {
        key: "csharpsquid:S2933",
        actions: &["csharp.s2933.add-readonly"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Complete project field identity and all write-site facts, including partial files.",
    },
    Contract {
        key: "csharpsquid:S2934",
        actions: &[
            "csharp.s2934.add-reference-constraint",
            "csharp.s2934.remove-useless-assignment",
        ],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove generic field/property symbols and preserve the two upstream remedy choices.",
    },
    Contract {
        key: "csharpsquid:S2955",
        actions: &["csharp.s2955.use-default-value"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove generic parameter identity and replace the null check with default(T).",
    },
    Contract {
        key: "csharpsquid:S3005",
        actions: &["csharp.s3005.remove-threadstatic"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.ThreadStaticAttribute and exact instance field declaration.",
    },
    Contract {
        key: "csharpsquid:S3052",
        actions: &["csharp.s3052.remove-default-initializer"],
        availability: Availability::Native,
        prerequisite: "Exact field declarator initializer whose value is the declared type default.",
    },
    Contract {
        key: "csharpsquid:S3169",
        actions: &["csharp.s3169.change-orderby-to-thenby"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.Linq OrderBy/OrderByDescending chain and key selector binding.",
    },
    Contract {
        key: "csharpsquid:S3217",
        actions: &["csharp.s3217.change-foreach-type"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove foreach variable and collection element symbols before adding OfType<T>.",
    },
    Contract {
        key: "csharpsquid:S3234",
        actions: &["csharp.s3234.remove-suppress-finalize"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.GC.SuppressFinalize invocation and complete type/finalizer facts.",
    },
    Contract {
        key: "csharpsquid:S3235",
        actions: &["csharp.s3235.remove-redundant-parentheses"],
        availability: Availability::Native,
        prerequisite: "Empty argument list on an object creation with initializer or an attribute.",
    },
    Contract {
        key: "csharpsquid:S3240",
        actions: &["csharp.s3240.simplify-condition"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove built-in bool operands and preserve conditional evaluation semantics.",
    },
    Contract {
        key: "csharpsquid:S3253",
        actions: &["csharp.s3253.remove-redundant-constructor"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove constructor/finalizer declaration is compiler-equivalent and owns no attributes/trivia.",
    },
    Contract {
        key: "csharpsquid:S3254",
        actions: &[
            "csharp.s3254.remove-default-argument",
            "csharp.s3254.remove-default-arguments-with-names",
        ],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove exact overload/parameter binding and preserve both upstream remedies: plain removal and removal with necessary named arguments.",
    },
    Contract {
        key: "csharpsquid:S3257",
        actions: &["csharp.s3257.remove-array-element-type"],
        availability: Availability::Native,
        prerequisite: "Implicit array creation with an explicit element type and initializer.",
    },
    Contract {
        key: "csharpsquid:S3261",
        actions: &["csharp.s3261.remove-empty-namespace"],
        availability: Availability::Native,
        prerequisite: "Exact empty namespace declaration.",
    },
    Contract {
        key: "csharpsquid:S3262",
        actions: &["csharp.s3262.add-params"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove overridden/interface parameter identity and compatible params element type.",
    },
    Contract {
        key: "csharpsquid:S3265",
        actions: &["csharp.s3265.add-flags-attribute"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove the exact non-[Flags] enum symbol before adding [Flags].",
    },
    Contract {
        key: "csharpsquid:S3353",
        actions: &["csharp.s3353.add-const"],
        availability: Availability::Native,
        prerequisite: "Exact primitive local with one literal initializer and no captured/write use.",
    },
    Contract {
        key: "csharpsquid:S3440",
        actions: &["csharp.s3440.remove-useless-condition"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove condition/assignment symbols and branch side-effect equivalence.",
    },
    Contract {
        key: "csharpsquid:S3441",
        actions: &["csharp.s3441.remove-anonymous-name"],
        availability: Availability::Native,
        prerequisite: "Anonymous member name and value are the same exact identifier expression.",
    },
    Contract {
        key: "csharpsquid:S3445",
        actions: &["csharp.s3445.use-bare-throw"],
        availability: Availability::Native,
        prerequisite: "Exact throw statement inside a catch; replacement preserves catch scope.",
    },
    Contract {
        key: "csharpsquid:S3447",
        actions: &["csharp.s3447.remove-optional-attribute"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.Runtime.InteropServices.OptionalAttribute on the exact ref/out parameter.",
    },
    Contract {
        key: "csharpsquid:S3450",
        actions: &["csharp.s3450.add-optional-attribute"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.Runtime.InteropServices.DefaultParameterValueAttribute and target parameter.",
    },
    Contract {
        key: "csharpsquid:S3451",
        actions: &["csharp.s3451.use-default-parameter-value-attribute"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.ComponentModel.DefaultValueAttribute and preserve its argument syntax.",
    },
    Contract {
        key: "csharpsquid:S3456",
        actions: &["csharp.s3456.remove-tochararray"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.String receiver and all indexing/iteration uses of the conversion.",
    },
    Contract {
        key: "csharpsquid:S3458",
        actions: &["csharp.s3458.remove-empty-case"],
        availability: Availability::Native,
        prerequisite: "Exact empty case section immediately falling through to default.",
    },
    Contract {
        key: "csharpsquid:S3532",
        actions: &["csharp.s3532.remove-empty-default"],
        availability: Availability::Native,
        prerequisite: "Exact default section containing only break statements.",
    },
    Contract {
        key: "csharpsquid:S3600",
        actions: &["csharp.s3600.remove-params"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove override parameter identity and base signature compatibility.",
    },
    Contract {
        key: "csharpsquid:S3604",
        actions: &["csharp.s3604.remove-redundant-initializer"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove the exact member initializer and every constructor assignment to that same field; exclude nested callables and preserve initializer trivia.",
    },
    Contract {
        key: "csharpsquid:S4201",
        actions: &["csharp.s4201.remove-redundant-null-check"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove stable local/field identity and non-overloaded null comparison.",
    },
    Contract {
        key: "csharpsquid:S4581",
        actions: &["csharp.s4581.use-guid-empty"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.Guid.NewGuid binding and intentional empty-value semantics.",
    },
    Contract {
        key: "csharpsquid:S6610",
        actions: &["csharp.s6610.convert-to-char"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.String StartsWith/EndsWith overload and preserve literal value.",
    },
    Contract {
        key: "csharpsquid:S6613",
        actions: &["csharp.s6613.use-linkedlist-property"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove System.Collections.Generic.LinkedList<T> receiver and property binding.",
    },
    Contract {
        key: "csharpsquid:S6961",
        actions: &["csharp.s6961.change-to-controllerbase"],
        availability: Availability::ProjectSemantic,
        prerequisite: "Prove Microsoft.AspNetCore.Mvc.Controller inheritance and required API compatibility.",
    },
];
/// Return the canonical static action identifier declared by the frozen
/// upstream contract inventory.
///
/// Semantic helper output is untrusted JSON at this boundary; accepting only
/// IDs present in this table prevents a helper typo from becoming a client
/// action while keeping one source of truth for the inventory.
pub(crate) fn canonical_action_id(id: &str) -> Option<&'static str> {
    for contract in CSHARP_QUICKFIX_CONTRACTS {
        if let Some(action) = contract
            .actions
            .iter()
            .copied()
            .find(|candidate| *candidate == id)
        {
            return Some(action);
        }
    }
    None
}

/// Semantic facts supplied by the C# project analyzer.  A source-only call
/// intentionally cannot satisfy this trait: semantic rewrites must be
/// suppressed unless the complete project model proves the exact finding.
pub(crate) trait QuickFixSemanticFacts {
    fn is_complete(&self) -> bool;

    /// `start`/`end` are UTF-8 offsets of the finding's primary range.
    fn proves(&self, key: &str, start: usize, end: usize, source: &str) -> bool;

    /// Return compiler-planned actions for a project-semantic provider.
    ///
    /// The C# syntax analyzer never fabricates these edits: callers must
    /// produce them from exact symbols and project-wide data.  An empty
    /// result keeps the provider unavailable when its prerequisite is not
    /// implemented.  Multiple entries are required for upstream providers
    /// that expose distinct alternative remedies.
    fn plans(&self, _key: &str, _start: usize, _end: usize, _source: &str) -> Vec<SemanticPlan> {
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SemanticPlan {
    pub(crate) id: &'static str,
    pub(crate) message: String,
    pub(crate) edits: Vec<TextEdit>,
}

/// Parse and attach source-only suggestions.  Project callers should prefer
/// [`attach_fixes_from_tree`] from their existing analysis tree.
pub(crate) fn attach_fixes(
    source: &str,
    options: &AnalyzerOptions,
    report: &mut FileReport,
    facts: Option<&dyn QuickFixSemanticFacts>,
) {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .expect("tree-sitter-c-sharp grammar is compatible");
    let tree = parser
        .parse(source, None)
        .expect("parse always yields a tree");
    attach_fixes_from_tree(tree.root_node(), source, options, report, facts);
}

/// Attach C# suggestions while borrowing the caller's already parsed tree.
pub(crate) fn attach_fixes_from_tree(
    root: Node<'_>,
    source: &str,
    options: &AnalyzerOptions,
    report: &mut FileReport,
    facts: Option<&dyn QuickFixSemanticFacts>,
) {
    for issue in &mut report.issues {
        let Some((start, end)) = issue_offsets(issue, source) else {
            continue;
        };
        let Some(key) = canonical_rule_key(&issue.rule_key) else {
            continue;
        };
        let dispatch = FixDispatch {
            root,
            source,
            options,
            facts,
            key,
            start,
            end,
        };
        dispatch_fixes(&dispatch, issue);
    }
}

struct FixDispatch<'tree, 'source, 'options, 'facts> {
    root: Node<'tree>,
    source: &'source str,
    options: &'options AnalyzerOptions,
    facts: Option<&'facts dyn QuickFixSemanticFacts>,
    key: &'static str,
    start: usize,
    end: usize,
}

fn canonical_rule_key(key: &str) -> Option<&'static str> {
    match key {
        "csharpsquid:S1006" => Some("csharpsquid:S1006"),
        "csharpsquid:S1116" => Some("csharpsquid:S1116"),
        "csharpsquid:S1125" => Some("csharpsquid:S1125"),
        "csharpsquid:S1128" => Some("csharpsquid:S1128"),
        "csharpsquid:S1155" => Some("csharpsquid:S1155"),
        "csharpsquid:S1172" => Some("csharpsquid:S1172"),
        "csharpsquid:S1185" => Some("csharpsquid:S1185"),
        "csharpsquid:S1186" => Some("csharpsquid:S1186"),
        "csharpsquid:S125" => Some("csharpsquid:S125"),
        "csharpsquid:S1451" => Some("csharpsquid:S1451"),
        "csharpsquid:S1939" => Some("csharpsquid:S1939"),
        "csharpsquid:S1905" => Some("csharpsquid:S1905"),
        "csharpsquid:S1940" => Some("csharpsquid:S1940"),
        "csharpsquid:S2219" => Some("csharpsquid:S2219"),
        "csharpsquid:S2290" => Some("csharpsquid:S2290"),
        "csharpsquid:S2328" => Some("csharpsquid:S2328"),
        "csharpsquid:S2333" => Some("csharpsquid:S2333"),
        "csharpsquid:S2761" => Some("csharpsquid:S2761"),
        "csharpsquid:S2737" => Some("csharpsquid:S2737"),
        "csharpsquid:S2933" => Some("csharpsquid:S2933"),
        "csharpsquid:S2934" => Some("csharpsquid:S2934"),
        "csharpsquid:S2955" => Some("csharpsquid:S2955"),
        "csharpsquid:S3005" => Some("csharpsquid:S3005"),
        "csharpsquid:S3052" => Some("csharpsquid:S3052"),
        "csharpsquid:S3169" => Some("csharpsquid:S3169"),
        "csharpsquid:S3217" => Some("csharpsquid:S3217"),
        "csharpsquid:S3234" => Some("csharpsquid:S3234"),
        "csharpsquid:S3235" => Some("csharpsquid:S3235"),
        "csharpsquid:S3240" => Some("csharpsquid:S3240"),
        "csharpsquid:S3253" => Some("csharpsquid:S3253"),
        "csharpsquid:S3254" => Some("csharpsquid:S3254"),
        "csharpsquid:S3257" => Some("csharpsquid:S3257"),
        "csharpsquid:S3261" => Some("csharpsquid:S3261"),
        "csharpsquid:S3262" => Some("csharpsquid:S3262"),
        "csharpsquid:S3353" => Some("csharpsquid:S3353"),
        "csharpsquid:S3441" => Some("csharpsquid:S3441"),
        "csharpsquid:S3445" => Some("csharpsquid:S3445"),
        "csharpsquid:S3447" => Some("csharpsquid:S3447"),
        "csharpsquid:S3458" => Some("csharpsquid:S3458"),
        "csharpsquid:S3532" => Some("csharpsquid:S3532"),
        "csharpsquid:S3265" => Some("csharpsquid:S3265"),
        "csharpsquid:S3440" => Some("csharpsquid:S3440"),
        "csharpsquid:S3450" => Some("csharpsquid:S3450"),
        "csharpsquid:S3451" => Some("csharpsquid:S3451"),
        "csharpsquid:S3456" => Some("csharpsquid:S3456"),
        "csharpsquid:S3604" => Some("csharpsquid:S3604"),
        "csharpsquid:S4201" => Some("csharpsquid:S4201"),
        "csharpsquid:S4581" => Some("csharpsquid:S4581"),
        "csharpsquid:S3600" => Some("csharpsquid:S3600"),
        "csharpsquid:S6610" => Some("csharpsquid:S6610"),
        "csharpsquid:S6613" => Some("csharpsquid:S6613"),
        "csharpsquid:S6961" => Some("csharpsquid:S6961"),
        "csharpsquid:S818" => Some("csharpsquid:S818"),
        "csharpsquid:S1858" => Some("csharpsquid:S1858"),
        _ => None,
    }
}

fn is_delegated_semantic_key(key: &str) -> bool {
    matches!(
        key,
        "csharpsquid:S1006"
            | "csharpsquid:S1155"
            | "csharpsquid:S1172"
            | "csharpsquid:S1185"
            | "csharpsquid:S1186"
            | "csharpsquid:S1939"
            | "csharpsquid:S2219"
            | "csharpsquid:S2328"
            | "csharpsquid:S2737"
            | "csharpsquid:S2934"
            | "csharpsquid:S2955"
            | "csharpsquid:S3169"
            | "csharpsquid:S3217"
            | "csharpsquid:S3240"
            | "csharpsquid:S3253"
            | "csharpsquid:S3254"
            | "csharpsquid:S3265"
            | "csharpsquid:S3440"
            | "csharpsquid:S3450"
            | "csharpsquid:S3451"
            | "csharpsquid:S3456"
            | "csharpsquid:S3604"
            | "csharpsquid:S4201"
            | "csharpsquid:S4581"
            | "csharpsquid:S6961"
    )
}
fn semantic_ok_for(context: &FixDispatch<'_, '_, '_, '_>) -> bool {
    semantic_ok(
        context.facts,
        context.key,
        context.start,
        context.end,
        context.source,
    )
}

fn dispatch_fixes(context: &FixDispatch<'_, '_, '_, '_>, issue: &mut Issue) {
    if is_delegated_semantic_key(context.key) {
        delegated_semantic(
            context.facts,
            context.key,
            context.start,
            context.end,
            context.source,
            issue,
        );
        return;
    }
    dispatch_tree_fixes(context, issue);
    dispatch_text_fixes(context, issue);
}

fn dispatch_tree_fixes(context: &FixDispatch<'_, '_, '_, '_>, issue: &mut Issue) {
    match context.key {
        "csharpsquid:S1116" => {
            s1116(
                context.root,
                context.source,
                issue,
                context.start,
                context.end,
            );
        }
        "csharpsquid:S1128" if semantic_ok_for(context) => {
            s1128(context.root, context.source, issue);
        }
        "csharpsquid:S125" => {
            s125(context.root, context.source, issue);
        }
        "csharpsquid:S1940" if semantic_ok_for(context) => {
            s1940(context.root, context.source, issue);
        }
        "csharpsquid:S2933" if semantic_ok_for(context) => {
            s2933(context.root, context.source, issue);
        }
        "csharpsquid:S3005" if semantic_ok_for(context) => {
            s3005(context.root, context.source, issue);
        }
        "csharpsquid:S3052" => {
            s3052(context.root, context.source, issue);
        }
        "csharpsquid:S3234" if semantic_ok_for(context) => {
            s3234(context.root, context.source, issue);
        }
        "csharpsquid:S3257" => {
            s3257(context.root, context.source, issue);
        }
        "csharpsquid:S3261" => {
            s3261(context.root, context.source, issue);
        }
        "csharpsquid:S3262" if semantic_ok_for(context) => {
            s3262(context.root, context.source, issue);
        }
        "csharpsquid:S3353" => {
            s3353(context.root, context.source, issue);
        }
        "csharpsquid:S3445" => {
            s3445(context.root, context.source, issue);
        }
        "csharpsquid:S3447" if semantic_ok_for(context) => {
            s3447(context.root, context.source, issue);
        }
        "csharpsquid:S3458" => {
            s3458(context.root, context.source, issue);
        }
        "csharpsquid:S3532" => {
            s3532(context.root, context.source, issue);
        }
        "csharpsquid:S3600" if semantic_ok_for(context) => {
            s3600(context.root, context.source, issue);
        }
        "csharpsquid:S6610" if semantic_ok_for(context) => {
            s6610(context.root, context.source, issue);
        }
        "csharpsquid:S6613" if semantic_ok_for(context) => {
            s6613(context.root, context.source, issue);
        }
        _ => {}
    }
}

fn dispatch_text_fixes(context: &FixDispatch<'_, '_, '_, '_>, issue: &mut Issue) {
    match context.key {
        "csharpsquid:S1125" if semantic_ok_for(context) => {
            remove_word(
                context.source,
                context.start,
                context.end,
                issue,
                "Remove the unnecessary Boolean literal(s).",
                "csharp.s1125.remove-boolean-literal",
            );
        }
        "csharpsquid:S1451" => {
            s1451(context.source, context.options, issue);
        }
        "csharpsquid:S818" => {
            s818(context.source, context.start, context.end, issue);
        }
        "csharpsquid:S1858" => {
            replace_action(
                context.source,
                issue,
                context.start,
                context.end,
                "",
                "Remove redundant 'ToString' call",
                "csharp.s1858.remove-redundant-tostring",
            );
        }
        "csharpsquid:S1905" => {
            // Compiler-backed As/Enumerable.Cast/OfType alternatives
            // come only from the complete Roslyn plan. The local scalar
            // CastExpression branch remains the narrow fallback.
            s1905_scalar(context.root, context.source, issue);
            delegated_semantic(
                context.facts,
                context.key,
                context.start,
                context.end,
                context.source,
                issue,
            );
        }
        "csharpsquid:S2290" => {
            remove_word(
                context.source,
                context.start,
                context.end,
                issue,
                "Remove 'virtual' keyword",
                "csharp.s2290.remove-virtual",
            );
        }
        "csharpsquid:S2333" if semantic_ok_for(context) => {
            s2333(context.source, context.start, context.end, issue);
        }
        "csharpsquid:S2761" if semantic_ok_for(context) => {
            replace_action(
                context.source,
                issue,
                context.start,
                context.end,
                "",
                "Remove repeated prefix operator(s)",
                "csharp.s2761.remove-repeated-prefix",
            );
        }
        "csharpsquid:S3235" => {
            replace_action(
                context.source,
                issue,
                context.start,
                context.end,
                "",
                "Remove redundant parentheses",
                "csharp.s3235.remove-redundant-parentheses",
            );
        }
        "csharpsquid:S3441" => {
            remove_word(
                context.source,
                context.start,
                context.end,
                issue,
                "Remove the redundant anonymous member name",
                "csharp.s3441.remove-anonymous-name",
            );
        }
        _ => {}
    }
}
fn semantic_ok(
    facts: Option<&dyn QuickFixSemanticFacts>,
    key: &str,
    start: usize,
    end: usize,
    source: &str,
) -> bool {
    facts.is_some_and(|facts| facts.is_complete() && facts.proves(key, start, end, source))
}
fn delegated_semantic(
    facts: Option<&dyn QuickFixSemanticFacts>,
    key: &str,
    start: usize,
    end: usize,
    source: &str,
    issue: &mut Issue,
) {
    let Some(facts) = facts else { return };
    if !facts.is_complete() || !facts.proves(key, start, end, source) {
        return;
    }
    for plan in facts.plans(key, start, end, source) {
        if plan.edits.is_empty() {
            continue;
        }
        let SemanticPlan { id, message, edits } = plan;
        if issue
            .alternatives
            .iter()
            .any(|alternative| alternative.id == id)
        {
            continue;
        }
        issue.add_alternative(id, message, edits);
    }
}
fn replace_action(
    source: &str,
    issue: &mut Issue,
    start: usize,
    end: usize,
    replacement: &str,
    message: &str,
    id: &'static str,
) {
    if start <= end && source.get(start..end).is_some() {
        add_action(issue, id, message, edit(source, start, end, replacement));
    }
}

fn add_action(issue: &mut Issue, id: &'static str, message: &str, edit: TextEdit) {
    if issue
        .alternatives
        .iter()
        .any(|alternative| alternative.id == id)
    {
        return;
    }
    issue.add_alternative(id, message.to_string(), vec![edit]);
}

fn edit(source: &str, start: usize, end: usize, replacement: &str) -> TextEdit {
    TextEdit {
        range: range_from_byte_offsets(start, end, source),
        replacement: replacement.to_string(),
    }
}

fn issue_offsets(issue: &Issue, source: &str) -> Option<(usize, usize)> {
    let start = position_to_byte(source, issue.range.start)?;
    let end = position_to_byte(source, issue.range.end)?;
    (start <= end).then_some((start, end))
}

fn position_to_byte(source: &str, position: Pos) -> Option<usize> {
    if position.line == 0 {
        return None;
    }
    let target_line = position.line as usize;
    let target_column = position.column as usize;
    let mut line = 1_usize;
    let mut column = 0_usize;
    if target_line == 1 && target_column == 0 {
        return Some(0);
    }
    for (byte, character) in source.char_indices() {
        if line == target_line && column == target_column {
            return Some(byte);
        }
        if character == '\n' {
            line += 1;
            column = 0;
        } else {
            column += 1;
        }
    }
    (line == target_line && column == target_column).then_some(source.len())
}

fn exact_node<'t>(root: Node<'t>, range: &Range, source: &str) -> Option<Node<'t>> {
    let mut found = None;
    walk_all(root, &mut |node| {
        if range_of(node, source) == *range {
            found = Some(node);
        }
    });
    found
}
fn exact_node_of_kind<'t>(
    root: Node<'t>,
    range: &Range,
    source: &str,
    kind: &str,
) -> Option<Node<'t>> {
    let mut found = None;
    walk_all(root, &mut |node| {
        if node.kind() == kind && range_of(node, source) == *range {
            found = Some(node);
        }
    });
    found
}

fn semantic_node<'t>(root: Node<'t>, range: &Range, source: &str, kind: &str) -> Option<Node<'t>> {
    exact_node(root, range, source).filter(|node| node.kind() == kind)
}

fn add_range_action(
    issue: &mut Issue,
    source: &str,
    start: usize,
    end: usize,
    id: &'static str,
    message: &str,
    replacement: &str,
) {
    if start <= end && source.get(start..end).is_some() {
        add_action(issue, id, message, edit(source, start, end, replacement));
    }
}

fn remove_word(
    source: &str,
    start: usize,
    end: usize,
    issue: &mut Issue,
    message: &str,
    id: &'static str,
) -> Vec<()> {
    let Some(word) = source.get(start..end) else {
        return Vec::new();
    };
    if word.trim().is_empty() {
        return Vec::new();
    }
    let mut edit_start = start;
    let mut edit_end = end;
    if source
        .as_bytes()
        .get(edit_end)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        edit_end += 1;
    } else if edit_start > 0
        && source
            .as_bytes()
            .get(edit_start - 1)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        edit_start -= 1;
    }
    add_range_action(issue, source, edit_start, edit_end, id, message, "");
    Vec::new()
}

fn line_span(source: &str, start: usize, end: usize) -> (usize, usize) {
    let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
    let mut line_end = source[end..]
        .find('\n')
        .map_or(source.len(), |index| end + index + 1);
    if line_end > source.len() {
        line_end = source.len();
    }
    (line_start, line_end)
}

fn s125_comment_edit(source: &str, comment: Node<'_>) -> TextEdit {
    let (line_start, line_end) = line_span(source, comment.start_byte(), comment.end_byte());
    let before = &source[line_start..comment.start_byte()];
    let after = &source[comment.end_byte()..line_end];
    if before.trim().is_empty() && after.trim().is_empty() {
        edit(source, line_start, line_end, "")
    } else {
        edit(source, comment.start_byte(), comment.end_byte(), "")
    }
}

fn s1116(root: Node<'_>, source: &str, issue: &mut Issue, _start: usize, _end: usize) -> Vec<()> {
    let Some(node) = collect_kinds(root, &["empty_statement"])
        .into_iter()
        .find(|node| range_of(*node, source) == issue.range)
    else {
        return Vec::new();
    };
    // Match S1116's detector guard: an empty loop body is deliberate, while
    // an empty statement nested in any other statement/block is removable.
    if node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "for_statement" | "foreach_statement" | "while_statement" | "do_statement"
        ) && parent.child_by_field_name("body") == Some(node)
    }) {
        return Vec::new();
    }
    add_range_action(
        issue,
        source,
        node.start_byte(),
        node.end_byte(),
        "csharp.s1116.remove-empty-statement",
        "Remove empty statement.",
        "",
    );
    Vec::new()
}
fn s1128(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(node) = semantic_node(root, &issue.range, source, "using_directive") else {
        return Vec::new();
    };
    let text = node_text(node, source);
    if text.starts_with("global ") || !text.trim_start().starts_with("using") {
        return Vec::new();
    }
    let (start, end) = line_span(source, node.start_byte(), node.end_byte());
    add_range_action(
        issue,
        source,
        start,
        end,
        "csharp.s1128.remove-unnecessary-using",
        "Remove this unnecessary 'using'.",
        "",
    );
    Vec::new()
}

fn s125(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(first) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    let first_text = node_text(first, source);
    if first.kind() != "comment" || !first_text.starts_with("//") || first_text.starts_with("///") {
        return Vec::new();
    }

    let comments: Vec<_> = collect_kinds(root, &["comment"])
        .into_iter()
        .filter(|comment| {
            let text = node_text(*comment, source);
            text.starts_with("//") && !text.starts_with("///")
        })
        .collect();
    let Some(first_indexed) = comments
        .iter()
        .position(|comment| comment.start_byte() == first.start_byte())
    else {
        return Vec::new();
    };
    let mut edits = vec![s125_comment_edit(source, first)];
    let mut expected_next_row = first.end_position().row + 1;
    for comment in comments.into_iter().skip(first_indexed + 1) {
        if comment.start_position().row != expected_next_row {
            break;
        }
        edits.push(s125_comment_edit(source, comment));
        expected_next_row = comment.end_position().row + 1;
    }
    issue.add_alternative(
        "csharp.s125.remove-commented-out-code",
        "Remove commented out code",
        edits,
    );
    Vec::new()
}

fn s818(source: &str, start: usize, end: usize, issue: &mut Issue) -> Vec<()> {
    if source.get(start..end) == Some("l") {
        add_range_action(
            issue,
            source,
            start,
            end,
            "csharp.s818.uppercase-literal-suffix",
            "Make literal suffix upper case",
            "L",
        );
    }
    Vec::new()
}
fn s1451(source: &str, options: &AnalyzerOptions, issue: &mut Issue) -> Vec<()> {
    if options.header_format.is_empty()
        || options.header_is_regular_expression
        || !is_comment_template(&options.header_format)
    {
        return Vec::new();
    }
    let Some((start, end)) = s1451_edit_span(source) else {
        return Vec::new();
    };
    let replacement = s1451_replacement(source, &options.header_format);
    add_range_action(
        issue,
        source,
        start,
        end,
        "csharp.s1451.add-or-update-license-header",
        "Add or update license header",
        &replacement,
    );
    Vec::new()
}

fn is_comment_template(header: &str) -> bool {
    let trimmed = header.trim();
    if trimmed.starts_with("//") {
        return trimmed
            .lines()
            .all(|line| line.trim().is_empty() || line.trim_start().starts_with("//"));
    }
    trimmed.starts_with("/*") && trimmed.ends_with("*/")
}

/// Finds a safe insertion point after encoding and interpreter prefixes.
/// Existing comments, blank lines, directives, and other trivia remain
/// untouched because S1451 cannot prove that they belong to an old header.
fn s1451_edit_span(source: &str) -> Option<(usize, usize)> {
    let mut prefix_end = source
        .strip_prefix('\u{feff}')
        .map_or(0, |_| '\u{feff}'.len_utf8());
    if source
        .get(prefix_end..)
        .is_some_and(|text| text.starts_with("#!"))
    {
        let rest = &source[prefix_end..];
        let offset = rest
            .bytes()
            .position(|byte| byte == b'\r' || byte == b'\n')?;
        prefix_end += offset;
        if source.as_bytes().get(prefix_end) == Some(&b'\r')
            && source.as_bytes().get(prefix_end + 1) == Some(&b'\n')
        {
            prefix_end += 2;
        } else {
            prefix_end += 1;
        }
    }
    Some((prefix_end, prefix_end))
}

fn s1451_replacement(source: &str, header: &str) -> String {
    let line_ending = source_line_ending(source);
    let mut replacement = String::with_capacity(header.len() + line_ending.len());
    let mut chars = header.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                replacement.push_str(line_ending);
            }
            '\n' => replacement.push_str(line_ending),
            character => replacement.push(character),
        }
    }
    if replacement.contains("\\r\\n") {
        replacement = replacement.replace("\\r\\n", line_ending);
    }
    if !replacement.ends_with(line_ending) {
        replacement.push_str(line_ending);
    }
    replacement
}

fn source_line_ending(source: &str) -> &'static str {
    let bytes = source.as_bytes();
    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => return "\r\n",
            b'\r' => return "\r",
            b'\n' => return "\n",
            _ => {}
        }
    }
    "\n"
}

fn s1905_scalar(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    // The pinned Sonar provider delegates CastExpression fixes to IDE0004.
    // Keep only the existing local literal scalar subset as an explicitly
    // separate, syntax-safe action; As/Enumerable.Cast/OfType alternatives
    // must come from compiler-planned semantic facts.
    let Some(type_node) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    if !matches!(
        node_text(type_node, source),
        "bool"
            | "byte"
            | "char"
            | "decimal"
            | "double"
            | "float"
            | "int"
            | "long"
            | "sbyte"
            | "short"
            | "uint"
            | "ulong"
            | "ushort"
    ) {
        return Vec::new();
    }
    let Some(cast) = type_node
        .parent()
        .filter(|parent| parent.kind() == "cast_expression")
    else {
        return Vec::new();
    };
    let Some(value) = cast.child_by_field_name("value") else {
        return Vec::new();
    };
    let target = crate::cst::simple_name(node_text(type_node, source));
    let value_text = node_text(value, source);
    let compatible = match value.kind() {
        "integer_literal" => integer_literal_natural_type(value_text) == Some(target),
        "real_literal" => match target {
            "double" => !value_text.ends_with(['f', 'F', 'm', 'M']),
            "float" => value_text.ends_with(['f', 'F']),
            "decimal" => value_text.ends_with(['m', 'M']),
            _ => false,
        },
        "string_literal" => target == "string",
        "character_literal" => target == "char",
        "boolean_literal" => target == "bool",
        _ => false,
    };
    if !compatible {
        return Vec::new();
    }
    add_range_action(
        issue,
        source,
        cast.start_byte(),
        value.start_byte(),
        "csharp.s1905.remove-redundant-cast",
        "Remove redundant cast",
        "",
    );
    Vec::new()
}

fn s1940(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(unary) = semantic_node(root, &issue.range, source, "prefix_unary_expression") else {
        return Vec::new();
    };
    let Some(parenthesized) = unary
        .named_child(0)
        .filter(|node| node.kind() == "parenthesized_expression")
    else {
        return Vec::new();
    };
    let Some(binary) = parenthesized
        .named_child(0)
        .filter(|node| node.kind() == "binary_expression")
    else {
        return Vec::new();
    };
    let mut cursor = binary.walk();
    let Some(operator) = binary.children(&mut cursor).find(|node| !node.is_named()) else {
        return Vec::new();
    };
    let opposite = match node_text(operator, source) {
        "==" => "!=",
        "!=" => "==",
        _ => return Vec::new(),
    };
    let mut replacement = node_text(binary, source).to_string();
    let relative = operator.start_byte().saturating_sub(binary.start_byte());
    let operator_len = operator.end_byte().saturating_sub(operator.start_byte());
    if replacement.get(relative..relative + operator_len).is_none() {
        return Vec::new();
    }
    replacement.replace_range(relative..relative + operator_len, opposite);
    add_range_action(
        issue,
        source,
        unary.start_byte(),
        unary.end_byte(),
        "csharp.s1940.invert-equality",
        "Invert 'Boolean' check",
        &replacement,
    );
    Vec::new()
}

fn s2333(source: &str, start: usize, end: usize, issue: &mut Issue) -> Vec<()> {
    let Some(word) = source.get(start..end) else {
        return Vec::new();
    };
    if matches!(
        word.trim(),
        "partial" | "sealed" | "unsafe" | "checked" | "unchecked"
    ) {
        remove_word(
            source,
            start,
            end,
            issue,
            "Remove redundant modifier",
            "csharp.s2333.remove-redundant-modifier",
        );
    }
    Vec::new()
}
fn s2933(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(anchor) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    let Some(field) = anchor
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")
        .or_else(|| {
            anchor
                .parent()
                .and_then(|parent| parent.parent())
                .filter(|parent| parent.kind() == "variable_declarator")
        })
    else {
        return Vec::new();
    };
    let Some(variable_declaration) = field
        .parent()
        .filter(|parent| parent.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    let Some(declaration) = variable_declaration
        .parent()
        .filter(|parent| parent.kind() == "field_declaration")
    else {
        return Vec::new();
    };
    if node_text(declaration, source)
        .split_whitespace()
        .any(|part| part == "readonly")
    {
        return Vec::new();
    }
    let Some(type_node) = variable_declaration.child_by_field_name("type") else {
        return Vec::new();
    };
    let insert_at = type_node.start_byte();
    add_range_action(
        issue,
        source,
        insert_at,
        insert_at,
        "csharp.s2933.add-readonly",
        "Add 'readonly' keyword",
        "readonly ",
    );
    Vec::new()
}

fn attribute_edit_span(attribute: Node<'_>, source: &str) -> (usize, usize) {
    let Some(list) = attribute
        .parent()
        .filter(|parent| parent.kind() == "attribute_list")
    else {
        return (attribute.start_byte(), attribute.end_byte());
    };
    let mut cursor = list.walk();
    let children: Vec<Node<'_>> = list.children(&mut cursor).collect();
    let Some(index) = children
        .iter()
        .position(|child| child.id() == attribute.id())
    else {
        return (attribute.start_byte(), attribute.end_byte());
    };
    let attribute_count = children
        .iter()
        .filter(|child| child.kind() == "attribute")
        .count();
    let (mut start, mut end) = if attribute_count == 1 {
        (list.start_byte(), list.end_byte())
    } else {
        (attribute.start_byte(), attribute.end_byte())
    };
    if attribute_count > 1 {
        if children
            .get(index + 1)
            .is_some_and(|child| node_text(*child, source) == ",")
        {
            end = children[index + 1].end_byte();
            while source
                .as_bytes()
                .get(end)
                .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            {
                end += 1;
            }
        } else if index > 0
            && children
                .get(index - 1)
                .is_some_and(|child| node_text(*child, source) == ",")
        {
            start = children[index - 1].start_byte();
            while start > 0
                && source
                    .as_bytes()
                    .get(start - 1)
                    .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            {
                start -= 1;
            }
        }
    }
    let (line_start, line_end) = line_span(source, start, end);
    if source
        .get(line_start..line_end)
        .is_some_and(|line| line.trim() == source[start..end].trim())
    {
        (line_start, line_end)
    } else {
        (start, end)
    }
}
fn contains_comment(node: Node<'_>) -> bool {
    let mut found = false;
    walk_all(node, &mut |candidate| {
        if candidate.kind() == "comment" {
            found = true;
        }
    });
    found
}

fn s3005(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(attribute) = exact_node_of_kind(root, &issue.range, source, "attribute") else {
        return Vec::new();
    };
    if !node_text(attribute, source).contains("ThreadStatic") {
        return Vec::new();
    }
    if attribute
        .parent()
        .is_some_and(|parent| parent.kind() == "attribute_list" && contains_comment(parent))
    {
        return Vec::new();
    }
    let (start, mut end) = attribute_edit_span(attribute, source);
    let single_attribute = attribute.parent().is_some_and(|parent| {
        if parent.kind() != "attribute_list" {
            return false;
        }
        let mut cursor = parent.walk();
        parent
            .children(&mut cursor)
            .filter(|child| child.kind() == "attribute")
            .count()
            == 1
    });
    if single_attribute
        && source
            .as_bytes()
            .get(end)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        end += 1;
    }
    add_range_action(
        issue,
        source,
        start,
        end,
        "csharp.s3005.remove-threadstatic",
        "Remove 'ThreadStatic' attribute",
        "",
    );
    Vec::new()
}

fn s3052(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some((issue_start, issue_end)) = issue_offsets(issue, source) else {
        return Vec::new();
    };
    for field in collect_kinds(root, &["field_declaration"]) {
        for declarator in collect_kinds(field, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(initializer) = declarator_initializer(declarator, name) else {
                continue;
            };
            if issue_start > initializer.end_byte() || issue_end < initializer.start_byte() {
                continue;
            }
            let Some(relative) = source[name.end_byte()..initializer.start_byte()].find('=') else {
                continue;
            };
            let equal = name.end_byte() + relative;
            let mut edit_start = equal;
            while edit_start > name.end_byte()
                && source
                    .as_bytes()
                    .get(edit_start - 1)
                    .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            {
                edit_start -= 1;
            }
            add_range_action(
                issue,
                source,
                edit_start,
                initializer.end_byte(),
                "csharp.s3052.remove-default-initializer",
                "Remove redundant initializer",
                "",
            );
            return Vec::new();
        }
    }
    Vec::new()
}

fn s3234(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(invocation) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    if invocation.kind() != "invocation_expression" {
        return Vec::new();
    }
    let Some(statement) = invocation
        .parent()
        .filter(|parent| parent.kind() == "expression_statement")
    else {
        return Vec::new();
    };
    add_range_action(
        issue,
        source,
        statement.start_byte(),
        statement.end_byte(),
        "csharp.s3234.remove-suppress-finalize",
        "Remove useless 'SuppressFinalize' call",
        "",
    );
    Vec::new()
}

fn s3257(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some((issue_start, issue_end)) = issue_offsets(issue, source) else {
        return Vec::new();
    };
    for creation in collect_kinds(root, &["array_creation_expression"]) {
        if issue_start < creation.start_byte() || issue_end > creation.end_byte() {
            continue;
        }
        let text = node_text(creation, source);
        let Some(after_new) = text.strip_prefix("new ") else {
            continue;
        };
        let Some(brackets) = after_new.find("[]") else {
            continue;
        };
        if !after_new[brackets + 2..].contains('{') {
            continue;
        }
        let start = creation.start_byte();
        let end = start + 4 + brackets + 2;
        add_range_action(
            issue,
            source,
            start,
            end,
            "csharp.s3257.remove-array-element-type",
            "Remove the array type; it is redundant.",
            "new[]",
        );
        break;
    }
    Vec::new()
}

fn s3261(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(namespace) = semantic_node(root, &issue.range, source, "namespace_declaration") else {
        return Vec::new();
    };
    let (start, end) = line_span(source, namespace.start_byte(), namespace.end_byte());
    add_range_action(
        issue,
        source,
        start,
        end,
        "csharp.s3261.remove-empty-namespace",
        "Remove empty namespace",
        "",
    );
    Vec::new()
}

fn s3262(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(parameter) =
        exact_node(root, &issue.range, source).filter(|node| node.kind() == "parameter")
    else {
        return Vec::new();
    };
    let Some(type_node) = parameter.child_by_field_name("type") else {
        return Vec::new();
    };
    add_range_action(
        issue,
        source,
        type_node.start_byte(),
        type_node.start_byte(),
        "csharp.s3262.add-params",
        "Add the 'params' modifier",
        "params ",
    );
    Vec::new()
}

fn s3353(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(name) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    let Some(declarator) = name
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")
    else {
        return Vec::new();
    };
    let Some(variable) = declarator
        .parent()
        .filter(|parent| parent.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    if variable
        .parent()
        .is_none_or(|parent| parent.kind() != "local_declaration_statement")
    {
        return Vec::new();
    }
    let Some(type_node) = variable.child_by_field_name("type") else {
        return Vec::new();
    };
    add_range_action(
        issue,
        source,
        type_node.start_byte(),
        type_node.start_byte(),
        "csharp.s3353.add-const",
        "Add the 'const' modifier",
        "const ",
    );
    Vec::new()
}

fn s3445(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(throw) = semantic_node(root, &issue.range, source, "throw_statement") else {
        return Vec::new();
    };
    let text = node_text(throw, source);
    if !text.trim_start().starts_with("throw ") || !text.trim_end().ends_with(';') {
        return Vec::new();
    }
    add_range_action(
        issue,
        source,
        throw.start_byte(),
        throw.end_byte(),
        "csharp.s3445.use-bare-throw",
        "Change to 'throw;'",
        "throw;",
    );
    Vec::new()
}

fn s3447(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(anchor) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    let attribute = if anchor.kind() == "attribute" {
        anchor
    } else {
        let Some(attribute) = anchor
            .parent()
            .filter(|parent| parent.kind() == "attribute")
        else {
            return Vec::new();
        };
        attribute
    };
    if !node_text(attribute, source).contains("Optional") {
        return Vec::new();
    }
    let (start, mut end) = attribute_edit_span(attribute, source);
    while source
        .as_bytes()
        .get(end)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        end += 1;
    }
    add_range_action(
        issue,
        source,
        start,
        end,
        "csharp.s3447.remove-optional-attribute",
        "Remove 'Optional' attribute",
        "",
    );
    Vec::new()
}

fn s3458(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some((issue_start, issue_end)) = issue_offsets(issue, source) else {
        return Vec::new();
    };
    let mut section = None;
    walk_all(root, &mut |node| {
        if node.kind() == "switch_section"
            && node.start_byte() <= issue_start
            && issue_end <= node.end_byte()
        {
            section = Some(node);
        }
    });
    let Some(section) = section else {
        return Vec::new();
    };
    let Some((label_start, label_end)) = switch_case_label_span(section, issue_start, issue_end)
    else {
        return Vec::new();
    };
    let (line_start, line_end) = line_span(source, label_start, label_end);
    let (edit_start, edit_end) = if source[line_start..label_start].trim().is_empty()
        && source[label_end..line_end].trim().is_empty()
    {
        (line_start, line_end)
    } else {
        (label_start, label_end)
    };
    add_range_action(
        issue,
        source,
        edit_start,
        edit_end,
        "csharp.s3458.remove-empty-case",
        "Remove useless 'case'",
        "",
    );
    Vec::new()
}

fn switch_case_label_span(
    section: Node<'_>,
    issue_start: usize,
    issue_end: usize,
) -> Option<(usize, usize)> {
    let mut cursor = section.walk();
    let children: Vec<_> = section.children(&mut cursor).collect();
    let mut first = None;
    for (index, child) in children.iter().enumerate() {
        if child.kind() != "case" {
            continue;
        }
        let Some(colon) = children[index + 1..]
            .iter()
            .take_while(|candidate| !matches!(candidate.kind(), "case" | "default"))
            .find(|candidate| candidate.kind() == ":")
        else {
            continue;
        };
        let span = (child.start_byte(), colon.end_byte());
        if span == (issue_start, issue_end) {
            return Some(span);
        }
        if first.is_none() {
            first = Some(span);
        }
    }
    first
}

fn s3532(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(section) = semantic_node(root, &issue.range, source, "switch_section") else {
        return Vec::new();
    };
    remove_word(
        source,
        section.start_byte(),
        section.end_byte(),
        issue,
        "Remove empty 'default' clause",
        "csharp.s3532.remove-empty-default",
    );
    Vec::new()
}

fn s3600(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(params) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    if node_text(params, source).trim() != "params" {
        return Vec::new();
    }
    remove_word(
        source,
        params.start_byte(),
        params.end_byte(),
        issue,
        "Remove the 'params' modifier",
        "csharp.s3600.remove-params",
    );
    Vec::new()
}

fn s6610(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(name) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    let Some(invocation) = name
        .parent()
        .filter(|parent| parent.kind() == "member_access_expression")
        .and_then(|member| member.parent())
        .filter(|parent| parent.kind() == "invocation_expression")
    else {
        return Vec::new();
    };
    let Some(argument) = invocation
        .named_children(&mut invocation.walk())
        .find(|child| child.kind() == "argument_list")
        .and_then(|list| list.named_child(0))
        .and_then(|arg| arg.named_child(0))
    else {
        return Vec::new();
    };
    let literal = node_text(argument, source);
    if argument.kind() != "string_literal"
        || literal.len() != 3
        || !literal.starts_with('"')
        || !literal.ends_with('"')
    {
        return Vec::new();
    }
    let replacement = format!("'{}'", &literal[1..2]);
    add_range_action(
        issue,
        source,
        argument.start_byte(),
        argument.end_byte(),
        "csharp.s6610.convert-to-char",
        "Convert to char.",
        &replacement,
    );
    Vec::new()
}
fn s6613(root: Node<'_>, source: &str, issue: &mut Issue) -> Vec<()> {
    let Some(name) = exact_node(root, &issue.range, source) else {
        return Vec::new();
    };
    let Some(member) = name
        .parent()
        .filter(|parent| parent.kind() == "member_access_expression")
    else {
        return Vec::new();
    };
    let Some(invocation) = member
        .parent()
        .filter(|parent| parent.kind() == "invocation_expression")
    else {
        return Vec::new();
    };
    let Some(argument_list) = invocation
        .children(&mut invocation.walk())
        .find(|child| child.kind() == "argument_list")
    else {
        return Vec::new();
    };
    if argument_list.named_child_count() != 0 {
        return Vec::new();
    }
    add_range_action(
        issue,
        source,
        member.end_byte(),
        invocation.end_byte(),
        "csharp.s6613.use-linkedlist-property",
        "Replace extension method call with property",
        ".Value",
    );
    Vec::new()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use hoonarqube_ir::{FileMetrics, FileReport, Issue};

    struct TestSemanticFacts {
        complete: bool,
        proof: Option<(String, usize, usize)>,
        plans: Vec<SemanticPlan>,
    }

    impl TestSemanticFacts {
        fn new(key: &str, start: usize, end: usize, plans: Vec<SemanticPlan>) -> Self {
            Self {
                complete: true,
                proof: Some((key.to_string(), start, end)),
                plans,
            }
        }

        fn without_proof(plans: Vec<SemanticPlan>) -> Self {
            Self {
                complete: true,
                proof: None,
                plans,
            }
        }
    }

    impl QuickFixSemanticFacts for TestSemanticFacts {
        fn is_complete(&self) -> bool {
            self.complete
        }

        fn proves(&self, key: &str, start: usize, end: usize, source: &str) -> bool {
            self.complete
                && source.get(start..end).is_some()
                && self
                    .proof
                    .as_ref()
                    .is_some_and(|(candidate, candidate_start, candidate_end)| {
                        candidate == key && *candidate_start == start && *candidate_end == end
                    })
        }

        fn plans(&self, key: &str, start: usize, end: usize, source: &str) -> Vec<SemanticPlan> {
            if self.proves(key, start, end, source) {
                self.plans.clone()
            } else {
                Vec::new()
            }
        }
    }

    fn report_with_issue(
        source: &str,
        key: &str,
        message: &str,
        start: usize,
        end: usize,
    ) -> FileReport {
        FileReport {
            path: PathBuf::from("t.cs"),
            language: "csharpsquid".to_string(),
            issues: vec![Issue::new(
                key,
                message,
                range_from_byte_offsets(start, end, source),
            )],
            metrics: FileMetrics {
                lines: u32::try_from(source.lines().count()).expect("fixture line count fits u32"),
                code_lines: 1,
                comment_lines: 0,
            },
        }
    }

    #[test]
    fn s3005_selects_attribute_when_identifier_shares_the_issue_span() {
        let source = "using System;\nclass C { [ThreadStatic] int field; }\n";
        let start = source.find("ThreadStatic").expect("attribute name");
        let end = start + "ThreadStatic".len();
        let mut report = report_with_issue(
            source,
            "csharpsquid:S3005",
            "Remove the 'ThreadStatic' attribute from this definition.",
            start,
            end,
        );
        let facts = TestSemanticFacts::new("csharpsquid:S3005", start, end, Vec::new());

        attach_fixes(
            source,
            &AnalyzerOptions::default(),
            &mut report,
            Some(&facts),
        );

        let alternative = report.issues[0]
            .alternatives
            .first()
            .expect("S3005 action should be reachable");
        assert_eq!(alternative.id, "csharp.s3005.remove-threadstatic");
        let fixed = hoonarqube_ir::apply_fixes(source, &[&alternative.fix.edits[0]])
            .expect("native attribute edit should apply");
        assert_eq!(fixed, "using System;\nclass C { int field; }\n");
    }

    #[test]
    fn s3005_preserves_spacing_when_removing_one_of_multiple_attributes() {
        let source = "using System;\nclass C { [Obsolete, ThreadStatic] int field; }\n";
        let start = source.find("ThreadStatic").expect("attribute name");
        let end = start + "ThreadStatic".len();
        let mut report = report_with_issue(
            source,
            "csharpsquid:S3005",
            "Remove the 'ThreadStatic' attribute from this definition.",
            start,
            end,
        );
        let facts = TestSemanticFacts::new("csharpsquid:S3005", start, end, Vec::new());

        attach_fixes(
            source,
            &AnalyzerOptions::default(),
            &mut report,
            Some(&facts),
        );

        let alternative = report.issues[0]
            .alternatives
            .first()
            .expect("S3005 multi-attribute action should be reachable");
        let fixed = hoonarqube_ir::apply_fixes(source, &[&alternative.fix.edits[0]])
            .expect("multi-attribute edit should apply");
        assert_eq!(fixed, "using System;\nclass C { [Obsolete] int field; }\n");
    }

    #[test]
    fn s3005_refuses_attribute_list_with_comments() {
        let source = "using System;\nclass C { [ThreadStatic /*keep*/, Obsolete] int field; }\n";
        let start = source.find("ThreadStatic").expect("attribute name");
        let end = start + "ThreadStatic".len();
        let mut report = report_with_issue(
            source,
            "csharpsquid:S3005",
            "Remove the 'ThreadStatic' attribute from this definition.",
            start,
            end,
        );
        let facts = TestSemanticFacts::new("csharpsquid:S3005", start, end, Vec::new());

        attach_fixes(
            source,
            &AnalyzerOptions::default(),
            &mut report,
            Some(&facts),
        );

        assert!(
            report.issues[0].alternatives.is_empty(),
            "commented attribute lists must remain unavailable to avoid deleting separators"
        );
    }

    #[test]
    fn s3169_delegates_the_exact_project_action() {
        let source = "using System.Linq;\nclass C { void M(int[] items) { items.OrderBy(a => a).OrderByDescending(b => b); } }\n";
        let start = source
            .rfind("OrderByDescending")
            .expect("outer ordering method");
        let end = start + "OrderByDescending".len();
        let action = SemanticPlan {
            id: "csharp.s3169.change-orderby-to-thenby",
            message: "Change 'OrderBy' to 'ThenBy'".to_string(),
            edits: vec![edit(source, start, end, "ThenByDescending")],
        };
        let mut report = report_with_issue(
            source,
            "csharpsquid:S3169",
            "Use 'ThenBy' instead.",
            start,
            end,
        );
        let facts = TestSemanticFacts::new("csharpsquid:S3169", start, end, vec![action]);

        attach_fixes(
            source,
            &AnalyzerOptions::default(),
            &mut report,
            Some(&facts),
        );

        let alternative = report.issues[0]
            .alternatives
            .first()
            .expect("S3169 delegated action should be reachable");
        assert_eq!(alternative.id, "csharp.s3169.change-orderby-to-thenby");
        let fixed = hoonarqube_ir::apply_fixes(source, &[&alternative.fix.edits[0]])
            .expect("S3169 edit should apply");
        assert_eq!(
            fixed,
            "using System.Linq;\nclass C { void M(int[] items) { items.OrderBy(a => a).ThenByDescending(b => b); } }\n"
        );
    }

    #[test]
    fn semantic_actions_refuse_unproved_same_named_or_dynamic_shapes() {
        let cases = [
            (
                "class C { void M(dynamic items) { items.OrderBy(a => a).OrderBy(b => b); } }\n",
                "csharpsquid:S3169",
                "Use 'ThenBy' instead.",
                "OrderBy",
            ),
            (
                "using System;\nclass C { [ThreadStatic] static int field; }\n",
                "csharpsquid:S3005",
                "Remove the 'ThreadStatic' attribute from this definition.",
                "ThreadStatic",
            ),
        ];
        for (source, key, message, token) in cases {
            let start = source.rfind(token).expect("negative-case token");
            let end = start + token.len();
            let mut report = report_with_issue(source, key, message, start, end);
            let facts = TestSemanticFacts::without_proof(Vec::new());
            attach_fixes(
                source,
                &AnalyzerOptions::default(),
                &mut report,
                Some(&facts),
            );
            assert!(
                report.issues[0].alternatives.is_empty(),
                "{key} must remain unavailable without its exact semantic fact"
            );
        }
    }
    fn apply_s125(source: &str, marker: &str) -> String {
        let start = source.find(marker).expect("S125 comment marker");
        let end = start + marker.len();
        let mut report = report_with_issue(
            source,
            "csharpsquid:S125",
            "Remove this commented out code.",
            start,
            end,
        );
        attach_fixes(source, &AnalyzerOptions::default(), &mut report, None);
        let alternative = report.issues[0]
            .alternatives
            .first()
            .expect("S125 action should be reachable");
        assert_eq!(alternative.id, "csharp.s125.remove-commented-out-code");
        let edits = alternative.fix.edits.iter().collect::<Vec<_>>();
        hoonarqube_ir::apply_fixes(source, &edits).expect("S125 edit should apply")
    }

    #[test]
    fn s125_preserves_inline_code_and_mixed_comment_runs() {
        let source = "class C\n{\n    static void M()\n    {\n        System.Console.WriteLine(\"keep\"); // int removed = 1;\n        // int removed = 2;\n        System.Console.WriteLine(\"after\");\n    }\n}\n";
        let fixed = apply_s125(source, "// int removed = 1;");
        assert_eq!(
            fixed,
            "class C\n{\n    static void M()\n    {\n        System.Console.WriteLine(\"keep\"); \n        System.Console.WriteLine(\"after\");\n    }\n}\n"
        );
    }

    #[test]
    fn s125_preserves_live_prefix_after_full_comment_in_run() {
        let source = "class C\n{\n    static void M()\n    {\n        // int removed = 1;\n        System.Console.WriteLine(\"after\"); // int removed = 2;\n        System.Console.WriteLine(\"tail\");\n    }\n}\n";
        let fixed = apply_s125(source, "// int removed = 1;");
        assert_eq!(
            fixed,
            "class C\n{\n    static void M()\n    {\n        System.Console.WriteLine(\"after\"); \n        System.Console.WriteLine(\"tail\");\n    }\n}\n"
        );
    }

    #[test]
    fn s125_removes_full_comment_lines() {
        let source = "class C\n{\n    static void M()\n    {\n        // int removed = 1;\n        System.Console.WriteLine(\"after\");\n    }\n}\n";
        let fixed = apply_s125(source, "// int removed = 1;");
        assert_eq!(
            fixed,
            "class C\n{\n    static void M()\n    {\n        System.Console.WriteLine(\"after\");\n    }\n}\n"
        );
    }

    #[test]
    fn s125_stops_mixed_comment_run_at_non_line_comment() {
        let source = "class C\n{\n    static void M()\n    {\n        System.Console.WriteLine(\"keep\"); // int removed = 1;\n        /* boundary */\n        // int untouched = 2;\n        System.Console.WriteLine(\"after\");\n    }\n}\n";
        let fixed = apply_s125(source, "// int removed = 1;");
        assert_eq!(
            fixed,
            "class C\n{\n    static void M()\n    {\n        System.Console.WriteLine(\"keep\"); \n        /* boundary */\n        // int untouched = 2;\n        System.Console.WriteLine(\"after\");\n    }\n}\n"
        );
    }

    #[test]
    fn s125_refuses_documentation_comments() {
        let source = "class C\n{\n    /// int docs = 1;\n}\n";
        let start = source
            .find("/// int docs = 1;")
            .expect("documentation comment");
        let end = start + "/// int docs = 1;".len();
        let mut report = report_with_issue(
            source,
            "csharpsquid:S125",
            "Remove this commented out code.",
            start,
            end,
        );
        attach_fixes(source, &AnalyzerOptions::default(), &mut report, None);
        assert!(
            report.issues[0].alternatives.is_empty(),
            "documentation comments must remain unavailable"
        );
    }
}
