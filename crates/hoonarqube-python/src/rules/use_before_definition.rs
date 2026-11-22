use crate::engine::file_context::FileContext;
use crate::engine::scope::{BindingKind, LoadRecord, ScopeKind, suite_range};
use crate::support::{constant_truth, is_builtin_name, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Stmt, StmtIf};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::{HashMap, HashSet};

// --- python:S3827 — use before definition ------------------------------------

pub(crate) fn check_use_before_definition(
    file: &FileContext<'_>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let facts = file.file_facts();
    if facts.dynamic_names || facts.has_wildcard_import {
        return Vec::new();
    }
    let table = file.symbol_table();
    let mut issues = Vec::new();
    let mut local_loads: HashMap<usize, Vec<&LoadRecord>> = HashMap::new();
    for load in &table.resolved_loads {
        if load.in_annotation || load.target != Some(load.scope) {
            continue;
        }
        if table.scopes[load.scope].kind == ScopeKind::Function {
            local_loads.entry(load.scope).or_default().push(load);
            continue;
        }
        if load.scope != 0 || is_builtin_name(&load.name) {
            continue;
        }
        let Some(bindings) = table.scopes[0].bindings.get(&load.name) else {
            continue;
        };
        let Some(first_definition) = bindings.iter().map(|b| b.range.start()).min() else {
            continue;
        };
        if load.range.end() <= first_definition {
            issues.push(issue_at(
                "python:S3827",
                &format!("'{}' is used before it is defined.", load.name),
                load.range,
                index,
                source,
            ));
        }
    }

    let mut bodies = HashMap::new();
    for (scope, loads) in local_loads {
        if let Some(range) = table.scopes[scope].body_range {
            bodies.insert(range, (scope, loads));
        }
    }
    for function in &file.functions {
        let Some((scope, loads)) = bodies.remove(&suite_range(&function.body)) else {
            continue;
        };
        let mut bound = HashSet::new();
        let mut bindings = Vec::new();
        for (name, sites) in &table.scopes[scope].bindings {
            for site in sites {
                if site.kind == BindingKind::Parameter {
                    bound.insert(name.as_str());
                } else {
                    bindings.push((site.range, name.as_str()));
                }
            }
        }
        bindings.sort_unstable_by_key(|(range, _)| range.start());
        let mut reads: Vec<_> = loads
            .iter()
            .filter(|load| !bound.contains(load.name.as_str()))
            .map(|load| (load.range, load.name.as_str()))
            .collect();
        if bindings.is_empty() || reads.is_empty() {
            continue;
        }
        reads.sort_unstable_by_key(|(range, _)| range.start());
        let mut flow = LocalFlow {
            bindings,
            reads,
            missing: Vec::new(),
        };
        flow.suite(&function.body, bound);
        issues.extend(flow.missing.into_iter().map(|(range, name)| {
            issue_at(
                "python:S3827",
                &format!("{name} is used before it is defined. Move the definition before."),
                range,
                index,
                source,
            )
        }));
    }
    issues
}

type Names<'a> = HashSet<&'a str>;
type Occurrence<'a> = (TextRange, &'a str);

/// Track whether *any* path reaching a statement can bind each local. The
/// reference stays silent for a maybe-bound name, so merge surviving paths
/// with a union. Treat complex statements conservatively as opaque regions.
struct LocalFlow<'a> {
    bindings: Vec<Occurrence<'a>>,
    reads: Vec<Occurrence<'a>>,
    missing: Vec<Occurrence<'a>>,
}

impl<'a> LocalFlow<'a> {
    fn suite(&mut self, suite: &[Stmt], mut bound: Names<'a>) -> Option<Names<'a>> {
        for statement in suite {
            match statement {
                Stmt::If(branch) => bound = self.branches(branch, bound)?,
                Stmt::For(_) | Stmt::While(_) | Stmt::With(_) | Stmt::Try(_) | Stmt::Match(_) => {
                    self.bind_in(statement.range(), &mut bound);
                }
                _ => {
                    self.simple_region(statement.range(), &mut bound);
                    if matches!(statement, Stmt::Return(_) | Stmt::Raise(_)) {
                        return None;
                    }
                }
            }
        }
        Some(bound)
    }

    fn branches(&mut self, branch: &StmtIf, bound: Names<'a>) -> Option<Names<'a>> {
        let mut otherwise = Some(bound);
        let mut merged = None;
        let clauses = std::iter::once((Some(branch.test.as_ref()), branch.body.as_slice())).chain(
            branch
                .elif_else_clauses
                .iter()
                .map(|clause| (clause.test.as_ref(), clause.body.as_slice())),
        );
        for (test, body) in clauses {
            let Some(mut entry) = otherwise.take() else {
                break;
            };
            if let Some(test) = test {
                self.simple_region(test.range(), &mut entry);
                let truth = constant_truth(test);
                if truth != Some(true) {
                    otherwise = Some(entry.clone());
                }
                if truth == Some(false) {
                    continue;
                }
            }
            merge(&mut merged, self.suite(body, entry));
        }
        merge(&mut merged, otherwise);
        merged
    }

    fn bind_in(&self, range: TextRange, bound: &mut Names<'a>) {
        bound.extend(in_range(&self.bindings, range).map(|(_, name)| name));
    }

    fn simple_region(&mut self, range: TextRange, bound: &mut Names<'a>) {
        // Treat same-statement definitions as available while checking reads.
        // The reference does not report self-assignment or annotation-only
        // declarations here; expression-level evaluation is outside scope.
        self.bind_in(range, bound);
        self.missing
            .extend(in_range(&self.reads, range).filter(|(_, name)| !bound.contains(name)));
    }
}

fn merge<'a>(merged: &mut Option<Names<'a>>, next: Option<Names<'a>>) {
    if let Some(next) = next {
        if let Some(bound) = merged {
            bound.extend(next);
        } else {
            *merged = Some(next);
        }
    }
}

fn in_range<'a>(
    occurrences: &[Occurrence<'a>],
    range: TextRange,
) -> impl Iterator<Item = Occurrence<'a>> {
    let start = occurrences.partition_point(|(item, _)| item.start() < range.start());
    occurrences[start..]
        .iter()
        .copied()
        .take_while(move |(item, _)| item.start() < range.end())
        .filter(move |(item, _)| range.contains_range(*item))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3827_finds_locals_when_no_binding_can_reach_the_read() {
        let report = scan(include_str!("../../tests/fixtures/s3827_locals.py"));
        let ranges: Vec<_> = findings(&report, "python:S3827")
            .iter()
            .map(|issue| {
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.column,
                )
            })
            .collect();
        assert_eq!(
            ranges,
            [
                (7, 14, 19),
                (11, 10, 15),
                (33, 11, 16),
                (44, 10, 14),
                (60, 10, 14)
            ]
        );
    }
}
