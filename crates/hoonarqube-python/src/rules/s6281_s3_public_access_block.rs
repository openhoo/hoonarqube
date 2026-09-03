use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
}

#[derive(Clone, Copy)]
struct LexicalScope {
    range: TextRange,
    parent: Option<usize>,
    kind: ScopeKind,
}

#[derive(Clone, Copy)]
struct S3BindingEvent {
    start: TextSize,
    trusted: bool,
}

#[derive(Default)]
struct S3Bindings {
    module_aliases: HashSet<String>,
    imported_module_roots: HashSet<String>,
    bucket_names: HashSet<String>,
    block_public_access_names: HashSet<String>,
    events: HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
    scopes: Vec<LexicalScope>,
}

impl S3Bindings {
    fn collect(file_ctx: &FileContext<'_>) -> Self {
        let mut bindings = Self {
            scopes: lexical_scopes(file_ctx),
            ..Self::default()
        };
        for import in &file_ctx.imports {
            match import {
                AnyImport::Plain(import) => {
                    for alias in &import.names {
                        match alias.name.as_str() {
                            "aws_cdk" => {
                                bindings.imported_module_roots.insert(
                                    alias.asname.as_deref().unwrap_or("aws_cdk").to_string(),
                                );
                            }
                            "aws_cdk.aws_s3" => {
                                if let Some(asname) = alias.asname.as_deref() {
                                    bindings.module_aliases.insert(asname.to_string());
                                } else {
                                    bindings.imported_module_roots.insert("aws_cdk".to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
                AnyImport::From(import) => {
                    let Some(module) = import
                        .module
                        .as_ref()
                        .map(ruff_python_ast::Identifier::as_str)
                    else {
                        continue;
                    };
                    match module {
                        "aws_cdk" => {
                            for alias in &import.names {
                                match alias.name.as_str() {
                                    "aws_s3" => {
                                        bindings.module_aliases.insert(
                                            alias
                                                .asname
                                                .as_deref()
                                                .map_or("aws_s3", |asname| asname)
                                                .to_string(),
                                        );
                                    }
                                    "*" => {
                                        bindings.module_aliases.insert("aws_s3".to_string());
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "aws_cdk.aws_s3" => {
                            for alias in &import.names {
                                if alias.name.as_str() == "*" {
                                    bindings.bucket_names.insert("Bucket".to_string());
                                    bindings
                                        .block_public_access_names
                                        .insert("BlockPublicAccess".to_string());
                                    continue;
                                }
                                let local = alias
                                    .asname
                                    .as_deref()
                                    .map_or(alias.name.as_str(), |asname| asname);
                                match alias.name.as_str() {
                                    "Bucket" => {
                                        bindings.bucket_names.insert(local.to_string());
                                    }
                                    "BlockPublicAccess" => {
                                        bindings
                                            .block_public_access_names
                                            .insert(local.to_string());
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        for import in &file_ctx.imports {
            record_trusted_import_events(import, &bindings.scopes, &mut bindings.events);
        }
        let tracked_names = bindings.tracked_names();
        for stmt in &file_ctx.stmts {
            record_rebinding_events(stmt, &bindings.scopes, &tracked_names, &mut bindings.events);
        }
        for events_by_name in bindings.events.values_mut() {
            for events in events_by_name.values_mut() {
                events.sort_by_key(|event| event.start);
            }
        }
        bindings
    }

    fn tracked_names(&self) -> HashSet<String> {
        self.module_aliases
            .iter()
            .chain(&self.imported_module_roots)
            .chain(&self.bucket_names)
            .chain(&self.block_public_access_names)
            .cloned()
            .collect()
    }

    fn scope_for_offset(&self, at: TextSize) -> usize {
        self.scopes
            .iter()
            .enumerate()
            .filter(|(_, scope)| scope.range.start() <= at && at <= scope.range.end())
            .min_by_key(|(_, scope)| scope.range.end().to_u32() - scope.range.start().to_u32())
            .map_or(0, |(id, _)| id)
    }

    fn trusted_at(&self, name: &str, at: TextSize) -> bool {
        let mut scope_id = self.scope_for_offset(at);
        loop {
            if let Some(events) = self
                .events
                .get(&scope_id)
                .and_then(|events_by_name| events_by_name.get(name))
            {
                let index = events.partition_point(|event| event.start <= at);
                if let Some(event) = index.checked_sub(1).and_then(|index| events.get(index)) {
                    return event.trusted;
                }
            }
            let Some(parent) = self.scopes[scope_id].parent else {
                return false;
            };
            scope_id = parent;
        }
    }
}

fn lexical_scopes(file_ctx: &FileContext<'_>) -> Vec<LexicalScope> {
    let end = file_ctx
        .stmts
        .iter()
        .map(|stmt| stmt.range().end())
        .max()
        .unwrap_or_else(|| TextSize::new(0));
    let mut ranges = vec![(TextRange::new(TextSize::new(0), end), ScopeKind::Module)];
    for function in &file_ctx.functions {
        if let Some(range) = body_range(function.body.as_slice()) {
            ranges.push((range, ScopeKind::Function));
        }
    }
    for class in &file_ctx.classes {
        if let Some(range) = body_range(class.body.as_slice()) {
            ranges.push((range, ScopeKind::Class));
        }
    }

    let mut ordered = ranges
        .iter()
        .enumerate()
        .map(|(id, (range, kind))| (id, *range, *kind))
        .collect::<Vec<_>>();
    ordered.sort_unstable_by(|(_, left, _), (_, right, _)| {
        left.start()
            .cmp(&right.start())
            .then_with(|| right.end().cmp(&left.end()))
    });
    let mut parents = vec![None; ranges.len()];
    let mut active: Vec<usize> = Vec::new();
    for (id, range, _) in ordered {
        while active
            .last()
            .is_some_and(|candidate| !ranges[*candidate].0.contains_range(range))
        {
            active.pop();
        }
        if id != 0 {
            parents[id] = active
                .iter()
                .rev()
                .find(|candidate| ranges[**candidate].1 != ScopeKind::Class)
                .copied();
        }
        active.push(id);
    }
    ranges
        .into_iter()
        .enumerate()
        .map(|(id, (range, kind))| LexicalScope {
            range,
            parent: parents[id],
            kind,
        })
        .collect()
}

fn body_range(body: &[Stmt]) -> Option<TextRange> {
    Some(TextRange::new(
        body.first()?.range().start(),
        body.last()?.range().end(),
    ))
}

fn push_binding_event(
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
    scope_id: usize,
    name: &str,
    start: TextSize,
    trusted: bool,
) {
    events
        .entry(scope_id)
        .or_default()
        .entry(name.to_string())
        .or_default()
        .push(S3BindingEvent { start, trusted });
}

fn record_trusted_import_events(
    import: &AnyImport<'_>,
    scopes: &[LexicalScope],
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
) {
    let import_range = match import {
        AnyImport::Plain(import) => import.range(),
        AnyImport::From(import) => import.range(),
    };
    let scope_id = scope_for_range(scopes, import_range);
    match import {
        AnyImport::Plain(import) => {
            for alias in &import.names {
                let local = alias.asname.as_deref().unwrap_or_else(|| {
                    alias
                        .name
                        .as_str()
                        .split('.')
                        .next()
                        .unwrap_or(alias.name.as_str())
                });
                if alias.name.as_str() == "aws_cdk" || alias.name.as_str() == "aws_cdk.aws_s3" {
                    push_binding_event(events, scope_id, local, import_range.end(), true);
                }
            }
        }
        AnyImport::From(import) => {
            let Some(module) = import
                .module
                .as_ref()
                .map(ruff_python_ast::Identifier::as_str)
            else {
                return;
            };
            for alias in &import.names {
                let local = if module == "aws_cdk" && alias.name.as_str() == "*" {
                    "aws_s3"
                } else {
                    alias.asname.as_deref().unwrap_or(alias.name.as_str())
                };
                if module == "aws_cdk"
                    && (alias.name.as_str() == "aws_s3" || alias.name.as_str() == "*")
                {
                    push_binding_event(events, scope_id, local, import_range.end(), true);
                } else if module == "aws_cdk.aws_s3" {
                    if alias.name.as_str() == "*" {
                        push_binding_event(events, scope_id, "Bucket", import_range.end(), true);
                        push_binding_event(
                            events,
                            scope_id,
                            "BlockPublicAccess",
                            import_range.end(),
                            true,
                        );
                    } else if matches!(alias.name.as_str(), "Bucket" | "BlockPublicAccess") {
                        push_binding_event(events, scope_id, local, import_range.end(), true);
                    }
                }
            }
        }
    }
}

fn record_rebinding_events(
    stmt: &Stmt,
    scopes: &[LexicalScope],
    tracked_names: &HashSet<String>,
    events: &mut HashMap<usize, HashMap<String, Vec<S3BindingEvent>>>,
) {
    let mut names = Vec::new();
    let activation = match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                collect_target_names(target, &mut names);
            }
            Some(assign.value.end())
        }
        Stmt::AnnAssign(assign) => {
            collect_target_names(&assign.target, &mut names);
            assign.value.as_deref().map(Ranged::end)
        }
        Stmt::AugAssign(assign) => {
            collect_target_names(&assign.target, &mut names);
            Some(assign.value.end())
        }
        Stmt::For(for_stmt) => {
            collect_target_names(&for_stmt.target, &mut names);
            Some(for_stmt.iter.end())
        }
        Stmt::FunctionDef(function) => {
            names.push(function.name.to_string());
            Some(
                function
                    .body
                    .first()
                    .map_or_else(|| stmt.range().end(), Ranged::start),
            )
        }
        Stmt::ClassDef(class) => {
            names.push(class.name.to_string());
            Some(stmt.range().end())
        }
        _ => return,
    };
    let scope_id = scope_for_range(
        scopes,
        TextRange::new(stmt.range().start(), stmt.range().start()),
    );
    let activation = activation.or_else(|| {
        (scopes[scope_id].kind == ScopeKind::Function).then(|| scopes[scope_id].range.start())
    });
    let Some(activation) = activation else {
        return;
    };
    for name in names {
        if tracked_names.contains(&name) {
            push_binding_event(events, scope_id, &name, activation, false);
        }
    }
}

fn scope_for_range(scopes: &[LexicalScope], range: TextRange) -> usize {
    scopes
        .iter()
        .enumerate()
        .filter(|(_, scope)| scope.range.contains_range(range))
        .min_by_key(|(_, scope)| scope.range.end().to_u32() - scope.range.start().to_u32())
        .map_or(0, |(id, _)| id)
}

pub(crate) fn check_s6281_s3_public_access_block(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let bindings = S3Bindings::collect(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let at = call.range().start();
        if !is_s3_bucket_constructor(&call.func, &bindings, at) {
            continue;
        }
        let fully_blocked = keyword_value(&call.arguments, "block_public_access")
            .is_some_and(|value| is_safe_public_access_block(value, &bindings, at));
        if !fully_blocked {
            issues.push(issue_at(
                "python:S6281",
                "No Public Access Block configuration prevents public ACL/policies to be set on this S3 bucket. Make sure it is safe here.",
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}
// --- python:S6281 — S3 public access fully blocked --------------------------------

const PUBLIC_ACCESS_BLOCK_KEYS: [&str; 4] = [
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
];

fn is_safe_public_access_block(value: &Expr, bindings: &S3Bindings, at: TextSize) -> bool {
    match value {
        Expr::Attribute(attribute) => {
            attribute.attr.as_str() == "BLOCK_ALL"
                && is_block_public_access_constructor(&attribute.value, bindings, at)
        }
        Expr::Call(call) => {
            is_block_public_access_constructor(&call.func, bindings, at)
                && PUBLIC_ACCESS_BLOCK_KEYS
                    .iter()
                    .all(|key| keyword_value(&call.arguments, key).is_some_and(is_true_literal))
        }
        _ => false,
    }
}

fn is_s3_bucket_constructor(function: &Expr, bindings: &S3Bindings, at: TextSize) -> bool {
    match function {
        Expr::Name(name) => {
            bindings.bucket_names.contains(name.id.as_str())
                && bindings.trusted_at(name.id.as_str(), at)
        }
        Expr::Attribute(attribute) => {
            attribute.attr.as_str() == "Bucket" && is_s3_module(&attribute.value, bindings, at)
        }
        _ => false,
    }
}

fn is_block_public_access_constructor(
    function: &Expr,
    bindings: &S3Bindings,
    at: TextSize,
) -> bool {
    match function {
        Expr::Name(name) => {
            bindings
                .block_public_access_names
                .contains(name.id.as_str())
                && bindings.trusted_at(name.id.as_str(), at)
        }
        Expr::Attribute(attribute) => {
            attribute.attr.as_str() == "BlockPublicAccess"
                && is_s3_module(&attribute.value, bindings, at)
        }
        _ => false,
    }
}

fn is_s3_module(value: &Expr, bindings: &S3Bindings, at: TextSize) -> bool {
    match value {
        Expr::Name(name) => {
            bindings.module_aliases.contains(name.id.as_str())
                && bindings.trusted_at(name.id.as_str(), at)
        }
        Expr::Attribute(attribute) => {
            attribute.attr.as_str() == "aws_s3"
                && matches!(
                    attribute.value.as_ref(),
                    Expr::Name(name)
                        if bindings.imported_module_roots.contains(name.id.as_str())
                            && bindings.trusted_at(name.id.as_str(), at)
                )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};
    use std::fmt::Write as _;

    #[test]
    fn inspects_only_block_public_access_ast_values() {
        let bucket_with = |configuration: &str| {
            let source = format!(
                "from aws_cdk import aws_s3 as s3\n\
                 s3.Bucket(scope, \"assets\", block_public_access={configuration})\n"
            );
            findings(&scan(&source), "python:S6281").len()
        };

        // Missing configuration and unresolved/conditional values remain findings.
        assert_eq!(bucket_with("unknown"), 1);
        assert_eq!(
            bucket_with("enabled if condition else s3.BlockPublicAccess.BLOCK_ALL"),
            1
        );

        // Comments and strings containing proof text do not count as configuration.
        assert_eq!(
            bucket_with(
                "unknown,  # BlockPublicAccess.BLOCK_ALL block_public_acls=True block_public_policy=True ignore_public_acls=True restrict_public_buckets=True\n                 "
            ),
            1
        );
        assert_eq!(
            bucket_with(
                "\"BlockPublicAccess.BLOCK_ALL block_public_acls=True block_public_policy=True ignore_public_acls=True restrict_public_buckets=True\""
            ),
            1
        );

        // Similar identifiers and explicitly false fields are unsafe.
        assert_eq!(bucket_with("s3.BlockPublicAccess.BLOCK_ALL_UNSAFE"), 1);
        assert_eq!(
            bucket_with(
                "s3.BlockPublicAccess(block_public_acls=False, block_public_policy=True, ignore_public_acls=True, restrict_public_buckets=True)  # block_public_acls=True"
            ),
            1
        );

        // Both supported complete configurations are safe.
        assert_eq!(bucket_with("s3.BlockPublicAccess.BLOCK_ALL"), 0);
        assert_eq!(
            bucket_with(
                "s3.BlockPublicAccess(block_public_acls=True, block_public_policy=True, ignore_public_acls=True, restrict_public_buckets=True)"
            ),
            0
        );
    }
    #[test]
    fn binds_s3_symbols_to_real_imports_and_requires_all_keys() {
        let complete = concat!(
            "from aws_cdk.aws_s3 import Bucket as S3Bucket, BlockPublicAccess as S3Block\n",
            "S3Bucket(scope, \"assets\", block_public_access=S3Block(\n",
            "    block_public_acls=True, block_public_policy=True,\n",
            "    ignore_public_acls=True, restrict_public_buckets=True,\n",
            "))\n",
        );
        assert!(findings(&scan(complete), "python:S6281").is_empty());

        let module_alias = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "s3.Bucket(scope, \"assets\", block_public_access=s3.BlockPublicAccess.BLOCK_ALL)\n",
        );
        assert!(findings(&scan(module_alias), "python:S6281").is_empty());

        let missing_key = concat!(
            "from aws_cdk.aws_s3 import Bucket, BlockPublicAccess\n",
            "Bucket(scope, \"assets\", block_public_access=BlockPublicAccess(\n",
            "    block_public_acls=True, block_public_policy=True,\n",
            "    ignore_public_acls=True,\n",
            "))\n",
        );
        assert_eq!(findings(&scan(missing_key), "python:S6281").len(), 1);
        let wildcard = concat!(
            "from aws_cdk.aws_s3 import *\n",
            "Bucket(scope, \"assets\", block_public_access=BlockPublicAccess.BLOCK_ALL)\n",
        );
        assert!(findings(&scan(wildcard), "python:S6281").is_empty());

        let root_imports = concat!(
            "import aws_cdk\n",
            "import aws_cdk as cdk\n",
            "aws_cdk.aws_s3.Bucket(scope, \"assets\", block_public_access=aws_cdk.aws_s3.BlockPublicAccess.BLOCK_ALL)\n",
            "cdk.aws_s3.Bucket(scope, \"other\", block_public_access=cdk.aws_s3.BlockPublicAccess.BLOCK_ALL)\n",
        );
        assert!(findings(&scan(root_imports), "python:S6281").is_empty());

        let lookalike_root = concat!(
            "import aws_cdk_fake as cdk\n",
            "cdk.aws_s3.Bucket(scope, \"lookalike\", block_public_access=cdk.aws_s3.BlockPublicAccess.BLOCK_ALL)\n",
        );
        assert!(findings(&scan(lookalike_root), "python:S6281").is_empty());

        let lookalikes = concat!(
            "from aws_cdk import aws_s3 as s3\n",
            "import aws_cdk.aws_s3_fake as fake_s3\n",
            "s3.Bucket(scope, \"assets\", block_public_access=s3.BlockPublicAccess.BLOCK_ALL)\n",
            "fake_s3.Bucket(scope, \"lookalike\", block_public_access=fake_s3.BlockPublicAccess.BLOCK_ALL)\n",
        );
        assert!(findings(&scan(lookalikes), "python:S6281").is_empty());
    }
    #[test]
    fn aliases_follow_lexical_rebinding() {
        let module_alias = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "s3.Bucket(scope, \"real\", block_public_access=unknown)\n",
            "s3 = fake_module\n",
            "s3.Bucket(scope, \"fake\", block_public_access=unknown)\n",
            "import aws_cdk.aws_s3 as s3\n",
            "s3.Bucket(scope, \"real_again\", block_public_access=unknown)\n",
        );
        assert_eq!(findings(&scan(module_alias), "python:S6281").len(), 2);

        let class_alias = concat!(
            "from aws_cdk.aws_s3 import Bucket\n",
            "Bucket(scope, \"real\", block_public_access=unknown)\n",
            "Bucket = fake_bucket\n",
            "Bucket(scope, \"fake\", block_public_access=unknown)\n",
        );
        assert_eq!(findings(&scan(class_alias), "python:S6281").len(), 1);
    }
    #[test]
    fn nested_scope_rebindings_do_not_escape() {
        let module_call = concat!(
            "from aws_cdk.aws_s3 import Bucket\n",
            "def helper():\n",
            "    Bucket = fake_bucket\n",
            "Bucket(scope, \"assets\", block_public_access=unknown)\n",
        );
        assert_eq!(findings(&scan(module_call), "python:S6281").len(), 1);

        let function_calls = concat!(
            "from aws_cdk.aws_s3 import Bucket\n",
            "def helper():\n",
            "    Bucket(scope, \"real\", block_public_access=unknown)\n",
            "    Bucket = fake_bucket\n",
            "    Bucket(scope, \"fake\", block_public_access=unknown)\n",
        );
        assert_eq!(findings(&scan(function_calls), "python:S6281").len(), 1);
    }

    #[test]
    fn rebindings_apply_after_evaluated_expressions() {
        let source = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "s3 = wrap(s3.Bucket(scope, \"rhs\", block_public_access=unknown))\n",
            "s3 = fake_module\n",
            "s3.Bucket(scope, \"after\", block_public_access=unknown)\n",
        );
        assert_eq!(findings(&scan(source), "python:S6281").len(), 1);
    }

    #[test]
    fn supported_import_bindings_keep_provenance_for_unsafe_calls() {
        let nested_import = concat!(
            "import aws_cdk.aws_s3\n",
            "aws_cdk.aws_s3.Bucket(scope, \"unsafe\", block_public_access=unknown)\n",
            "aws_cdk.aws_s3.Bucket(scope, \"safe\", block_public_access=aws_cdk.aws_s3.BlockPublicAccess.BLOCK_ALL)\n",
        );
        assert_eq!(findings(&scan(nested_import), "python:S6281").len(), 1);

        let root_wildcard = concat!(
            "from aws_cdk import *\n",
            "aws_s3.Bucket(scope, \"unsafe\", block_public_access=unknown)\n",
            "aws_s3.Bucket(scope, \"safe\", block_public_access=aws_s3.BlockPublicAccess.BLOCK_ALL)\n",
        );
        assert_eq!(findings(&scan(root_wildcard), "python:S6281").len(), 1);
    }

    #[test]
    fn method_lookups_skip_class_namespace() {
        let source = concat!(
            "from aws_cdk.aws_s3 import Bucket\n",
            "class C:\n",
            "    Bucket = fake_bucket\n",
            "    def build(self):\n",
            "        Bucket(scope, \"assets\", block_public_access=unknown)\n",
        );
        let report = scan(source);
        let found = findings(&report, "python:S6281");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 5);
    }

    #[test]
    fn class_definition_binds_name_after_body() {
        let source = concat!(
            "from aws_cdk.aws_s3 import Bucket\n",
            "class Bucket:\n",
            "    created = Bucket(scope, \"assets\", block_public_access=unknown)\n",
            "Bucket(scope, \"after\", block_public_access=unknown)\n",
        );
        let report = scan(source);
        let found = findings(&report, "python:S6281");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn value_less_annotations_follow_scope_semantics() {
        let module = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "s3: object\n",
            "s3.Bucket(scope, \"module\", block_public_access=unknown)\n",
        );
        let report = scan(module);
        let found = findings(&report, "python:S6281");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);

        let class = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "class C:\n",
            "    s3: object\n",
            "    s3.Bucket(scope, \"class\", block_public_access=unknown)\n",
        );
        let report = scan(class);
        let found = findings(&report, "python:S6281");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);

        let function = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "def build():\n",
            "    s3.Bucket(scope, \"function\", block_public_access=unknown)\n",
            "    s3: object\n",
        );
        assert!(findings(&scan(function), "python:S6281").is_empty());
    }

    #[test]
    fn non_aws_files_skip_s3_provenance_work() {
        let mut source = String::new();
        for index in 0..1024 {
            writeln!(&mut source, "def function_{index}():").unwrap();
            writeln!(&mut source, "    return {index}").unwrap();
        }
        assert!(findings(&scan(&source), "python:S6281").is_empty());
    }
}
