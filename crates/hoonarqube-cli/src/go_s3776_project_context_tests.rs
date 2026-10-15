use super::*;

const CALLER: &str = "package sample\nfunc inspect() { _, problem := supply(); if problem != nil { println(problem) } }\n";
const HELPER: &str = "package sample\nfunc supply() (int,error) { return 0,nil }\n";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-go-context-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("unique fixture directory");
        Self(path)
    }

    fn write(&self, name: &str, source: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, source).unwrap();
        path
    }

    fn pair(&self) -> [PathBuf; 2] {
        [
            self.write("consumer.go", CALLER),
            self.write("helper.go", HELPER),
        ]
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn options() -> AnalyzerOptionsBundle {
    let mut options = AnalyzerOptionsBundle::default();
    options.go.maximum_cognitive_complexity = 0;
    options
}

fn project_options(test: &[String], excluded: &[String]) -> ProjectAnalysisOptions {
    project_analysis_options(
        ProjectPatternLists {
            exclude: excluded,
            test_include: test,
            generated_include: &[],
            vendor_include: &[],
            duplication_exclude: &[],
        },
        100,
        10,
        10,
    )
    .unwrap()
}

fn collect(paths: &[PathBuf]) -> CollectedProjectInputs {
    collect_project_inputs(
        paths,
        &project_options(&[], &[]),
        options().profile,
        &mut Vec::new(),
    )
}

fn position(collected: &CollectedProjectInputs, path: &Path) -> usize {
    collected
        .pending
        .iter()
        .position(|input| input.path == path)
        .unwrap()
}

fn analyze(collected: &CollectedProjectInputs, path: &Path) -> ProjectFile {
    let context = GoProjectContext::build(collected).unwrap();
    read_and_analyze_project(
        &collected.pending[position(collected, path)],
        &collected.source_inventory,
        &options(),
        None,
        Some(&context),
        None,
    )
}

fn local(path: &Path, source: &str, classification: FileClassification) -> ProjectFile {
    analyze_project_file(path, source, &options(), classification, false)
}

fn assert_same(actual: &ProjectFile, expected: &ProjectFile) {
    assert_eq!(actual.path, expected.path);
    assert_eq!(actual.classification, expected.classification);
    assert_eq!(actual.report, expected.report);
    assert_eq!(actual.error, expected.error);
    assert_eq!(actual.duplication_excluded, expected.duplication_excluded);
    assert_eq!(actual.facts, expected.facts);
}

fn assert_supported(collected: &CollectedProjectInputs, path: &Path) {
    let mut expected = local(path, CALLER, FileClassification::Source);
    let report = expected.report.as_mut().unwrap();
    let before = report.issues.len();
    report.issues.retain(|issue| issue.rule_key != "go:S3776");
    assert_eq!(
        report.issues.len() + 1,
        before,
        "positive must actually change S3776"
    );
    assert_same(&analyze(collected, path), &expected);
}

#[test]
fn go_s3776_project_patterns_classification_is_authoritative() {
    let fixture = Fixture::new();
    let paths = fixture.pair();
    for (test, excluded) in [
        (vec!["**/helper.go".to_owned()], vec![]),
        (vec![], vec!["**/helper.go".to_owned()]),
    ] {
        let collected = collect_project_inputs(
            &paths,
            &project_options(&test, &excluded),
            options().profile,
            &mut Vec::new(),
        );
        assert_same(
            &analyze(&collected, &paths[0]),
            &local(&paths[0], CALLER, FileClassification::Source),
        );
    }
    let test_helper = fixture.write("supplier_test.go", HELPER);
    let collected = collect_project_inputs(
        &[paths[0].clone(), test_helper],
        &project_options(&[], &[]),
        options().profile,
        &mut Vec::new(),
    );
    assert_same(
        &analyze(&collected, &paths[0]),
        &local(&paths[0], CALLER, FileClassification::Source),
    );
    let source_helper = fixture.write("test_helpers.go", HELPER);
    let collected = collect(&[paths[0].clone(), source_helper]);
    assert_supported(&collected, &paths[0]);

    let collected = collect_project_inputs(
        &paths,
        &project_options(&["**/consumer.go".to_owned()], &[]),
        options().profile,
        &mut Vec::new(),
    );
    assert_same(
        &analyze(&collected, &paths[0]),
        &local(&paths[0], CALLER, FileClassification::Test),
    );
}

#[test]
fn go_s3776_project_input_none_refuses_whole_source_group() {
    let fixture = Fixture::new();
    let paths = fixture.pair();
    let other = [
        fixture.write("other/consumer.go", CALLER),
        fixture.write("other/helper.go", HELPER),
    ];
    let all = [
        paths[0].clone(),
        paths[1].clone(),
        other[0].clone(),
        other[1].clone(),
    ];
    for missing in &paths {
        let mut collected = collect(&all);
        assert_supported(&collected, &paths[0]);
        let position = position(&collected, missing);
        collected.pending[position].source_index = None;
        assert!(collected.semantic_input_complete);
        assert_same(
            &analyze(&collected, &paths[0]),
            &local(&paths[0], CALLER, FileClassification::Source),
        );
        assert_supported(&collected, &other[0]);
    }
}

#[test]
fn go_s3776_project_input_invalid_slot_refuses_group() {
    let fixture = Fixture::new();
    let paths = fixture.pair();
    for defect in [
        "index",
        "path",
        "classification",
        "bytes",
        "receipt",
        "physical",
    ] {
        let mut collected = collect(&paths);
        let helper_position = position(&collected, &paths[1]);
        let slot = collected.pending[helper_position].source_index.unwrap();
        match defect {
            "index" => collected.pending[helper_position].source_index = Some(usize::MAX),
            "path" => collected.source_inventory[slot].path = fixture.0.join("wrong.go"),
            "classification" => {
                collected.source_inventory[slot].classification = FileClassification::Test;
            }
            "bytes" => collected.source_inventory[slot]
                .source
                .push_str("// later bytes\n"),
            "receipt" => {
                collected.go_receipts.remove(&paths[1]);
            }
            "physical" => {
                collected
                    .go_receipts
                    .get_mut(&paths[1])
                    .unwrap()
                    .physical_path = None;
            }
            _ => unreachable!(),
        }
        assert_same(
            &analyze(&collected, &paths[0]),
            &local(&paths[0], CALLER, FileClassification::Source),
        );
    }
    let mut collected = collect(&paths);
    let target = position(&collected, &paths[0]);
    collected.pending[target].source_index = Some(usize::MAX);
    let actual = analyze(&collected, &paths[0]);
    assert!(actual.report.is_none());
    assert_eq!(
        actual.error.as_deref(),
        Some("source snapshot inventory index is invalid")
    );
}

#[test]
fn go_s3776_project_retention_limit_none_with_complete_flag_refuses_group() {
    let fixture = Fixture::new();
    let paths = fixture.pair();
    let mut collected = collect(&paths[..1]);
    collected.retained_bytes = MAX_RETAINED_SOURCE_BYTES;
    collect_retained_project_input(
        paths[1].clone(),
        FileClassification::Source,
        false,
        true,
        &mut collected,
    );
    assert_eq!(collected.source_inventory.len(), 1);
    assert!(
        collected.pending[position(&collected, &paths[1])]
            .source_index
            .is_none()
    );
    assert!(collected.semantic_input_complete);
    assert_same(
        &analyze(&collected, &paths[0]),
        &local(&paths[0], CALLER, FileClassification::Source),
    );
    // The target None branch keeps its bounded current read and diagnostic path.
    fs::write(&paths[1], [0xff]).unwrap();
    let actual = analyze(&collected, &paths[1]);
    assert!(actual.report.is_none());
    assert_eq!(actual.error.as_deref(), Some("source is not valid UTF-8"));
}

#[test]
fn go_s3776_project_unavailable_sources_keep_diagnostics() {
    let fixture = Fixture::new();
    let paths = fixture.pair();
    for defect in ["malformed", "utf8", "missing", "oversize", "unreadable"] {
        fs::write(&paths[1], HELPER).unwrap();
        match defect {
            "malformed" => fs::write(&paths[1], "package sample\nfunc broken( {").unwrap(),
            "utf8" => fs::write(&paths[1], [0xff]).unwrap(),
            "missing" => fs::remove_file(&paths[1]).unwrap(),
            "oversize" => fs::File::create(&paths[1])
                .unwrap()
                .set_len(17 * 1024 * 1024)
                .unwrap(),
            "unreadable" => (),
            _ => unreachable!(),
        }
        let mut collected = collect(&paths);
        if defect == "unreadable" {
            let helper = position(&collected, &paths[1]);
            collected.pending[helper].source_index = None;
            fs::remove_file(&paths[1]).unwrap();
            fs::create_dir(&paths[1]).unwrap();
        }
        assert_same(
            &analyze(&collected, &paths[0]),
            &local(&paths[0], CALLER, FileClassification::Source),
        );
        let failed = if collected.pending.iter().any(|input| input.path == paths[1]) {
            analyze(&collected, &paths[1])
        } else {
            collected.project_files.pop().unwrap()
        };
        assert!(failed.error.is_some(), "{defect}: {failed:?}");
        if defect == "malformed" {
            assert!(
                failed
                    .report
                    .as_ref()
                    .unwrap()
                    .issues
                    .iter()
                    .any(|issue| issue.rule_key == "go:S2260")
            );
        }
        if defect == "utf8" {
            assert_eq!(failed.error.as_deref(), Some("source is not valid UTF-8"));
        }
        if defect == "oversize" {
            assert!(failed.facts.as_ref().unwrap().error.is_some());
            assert!(failed.report.is_none());
        }
        let report = build_project_report(
            vec![analyze(&collected, &paths[0]), failed],
            paths.to_vec(),
            Vec::new(),
            &DuplicationOptions::default(),
        )
        .unwrap();
        assert!(!report.project.complete, "{defect}");
        if defect == "unreadable" {
            fs::remove_dir(&paths[1]).unwrap();
        }
    }
}

#[test]
fn go_s3776_projected_source_rejects_stale_context() {
    let fixture = Fixture::new();
    let paths = fixture.pair();
    let collected = collect(&paths);
    assert_supported(&collected, &paths[0]);
    let context = GoProjectContext::build(&collected).unwrap();
    let input = &collected.pending[position(&collected, &paths[0])];
    for projected in [
        format!("{CALLER}// projected\n"),
        CALLER.replace('\n', "\r\n"),
        CALLER.replace("inspect", "inspect世界"),
    ] {
        let actual = analyze_native_project_source(input, &projected, &options(), Some(&context));
        assert_same(
            &actual,
            &local(&paths[0], &projected, FileClassification::Source),
        );
    }
    for identity in ["normalized", "physical", "classification"] {
        let mut changed = collect(&paths);
        let receipt = changed.go_receipts.get_mut(&paths[0]).unwrap();
        match identity {
            "normalized" => receipt.normalized_path = fixture.0.join("other.go"),
            "physical" => receipt.physical_path = Some(fixture.0.join("other.go")),
            "classification" => receipt.classification = FileClassification::Test,
            _ => unreachable!(),
        }
        let input = &changed.pending[position(&changed, &paths[0])];
        let actual = analyze_native_project_source(input, CALLER, &options(), Some(&context));
        // The original context validates the original target. Exercise a changed
        // identity directly against that same immutable index.
        let receipt = changed.go_receipts.get(&paths[0]).unwrap();
        let actual_changed = hoonarqube_core::project::analyze_project_file_with_go_context(
            &paths[0],
            CALLER,
            &options(),
            FileClassification::Source,
            false,
            receipt.identity(true),
            &context.index,
        );
        assert_same(
            &actual_changed,
            &local(&paths[0], CALLER, FileClassification::Source),
        );
        assert_eq!(actual.report, analyze(&collected, &paths[0]).report);
    }
    fs::write(
        &paths[1],
        "package sample\nfunc supply() (int,*int) { return 0,nil }\n",
    )
    .unwrap();
    let rebuilt = collect(&paths);
    let new_context = GoProjectContext::build(&rebuilt).unwrap();
    assert_ne!(context.index.digest(), new_context.index.digest());
    assert_same(
        &analyze(&rebuilt, &paths[0]),
        &local(&paths[0], CALLER, FileClassification::Source),
    );
}

#[test]
fn go_s3776_fix_projection_uses_current_file_local_facts() {
    let fixture = Fixture::new();
    let paths = fixture.pair();
    let collected = collect(&paths);
    assert_supported(&collected, &paths[0]);
    let fix = crate::semantic_cli::FixAnalysisContext::load(
        &paths,
        &crate::project_features::SemanticOptions::default(),
        &options(),
    )
    .unwrap();
    for source in [
        CALLER.to_owned(),
        format!("{CALLER}// projected 🌍\r\n"),
        format!("{CALLER}{HELPER}").replacen("package sample\nfunc supply", "func supply", 1),
    ] {
        assert_eq!(
            fix.analyze(&paths[0], &source).unwrap(),
            hoonarqube_core::analyze(&paths[0], &source, &options())
        );
    }
    assert!(
        fix.analyze(&paths[0], CALLER)
            .unwrap()
            .unwrap()
            .issues
            .iter()
            .any(|issue| issue.rule_key == "go:S3776")
    );
}

#[test]
fn go_s3776_project_identity_receipts_are_order_independent() {
    let fixture = Fixture::new();
    let paths = fixture.pair();
    let mut first = collect(&paths);
    let context = GoProjectContext::build(&first).unwrap();
    let reversed = collect(&[paths[1].clone(), paths[0].clone()]);
    assert_eq!(
        context.index.digest(),
        GoProjectContext::build(&reversed).unwrap().index.digest()
    );
    first.pending.reverse();
    first.source_inventory.reverse();
    for input in &mut first.pending {
        input.source_index = input.source_index.map(|i| 1 - i);
    }
    assert_eq!(
        context.index.digest(),
        GoProjectContext::build(&first).unwrap().index.digest()
    );
    assert_supported(&first, &paths[0]);
    let before = context.index.digest().to_owned();
    first.go_receipts.get_mut(&paths[1]).unwrap().source_digest = Some([0; 32]);
    assert_ne!(
        before,
        GoProjectContext::build(&first).unwrap().index.digest()
    );
    assert_same(
        &analyze(&first, &paths[0]),
        &local(&paths[0], CALLER, FileClassification::Source),
    );
}
