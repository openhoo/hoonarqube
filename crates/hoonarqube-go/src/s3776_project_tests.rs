use std::path::{Path, PathBuf};

use hoonarqube_ir::{FileClassification, FileReport};

use super::{ProjectErrorIndex, ProjectSourceIdentity, ProjectSourceSnapshot};
use crate::{AnalyzerOptions, analyze, analyze_with_project_context};

const CALLER: &str = "package sample\nfunc inspect() { _, problem := supply(); if problem != nil { println(problem) } }\n";
const HELPER: &str = "package sample\nfunc supply() (int, error) { return 0, nil }\n";

#[derive(Clone)]
struct Member {
    path: PathBuf,
    physical: Option<PathBuf>,
    source: Option<String>,
    classification: FileClassification,
}

impl Member {
    fn new(path: &str, source: &str) -> Self {
        let path = Path::new("/virtual/pkg").join(path);
        Self {
            physical: Some(path.clone()),
            path,
            source: Some(source.to_owned()),
            classification: FileClassification::Source,
        }
    }

    fn identity(&self) -> ProjectSourceIdentity<'_> {
        ProjectSourceIdentity {
            normalized_path: &self.path,
            physical_path: self.physical.as_deref(),
            classification: self.classification,
        }
    }
}

fn build(members: &[Member]) -> ProjectErrorIndex {
    ProjectErrorIndex::build(
        &members
            .iter()
            .map(|m| ProjectSourceSnapshot {
                identity: m.identity(),
                source: m.source.as_deref(),
            })
            .collect::<Vec<_>>(),
    )
}

fn options() -> AnalyzerOptions {
    AnalyzerOptions {
        maximum_cognitive_complexity: 0,
        ..AnalyzerOptions::default()
    }
}

fn contextual(members: &[Member]) -> FileReport {
    let target = &members[0];
    analyze_with_project_context(
        target.path.clone(),
        target.source.as_deref().unwrap(),
        &options(),
        target.identity(),
        &build(members),
    )
}

fn local(member: &Member) -> FileReport {
    analyze(
        member.path.clone(),
        member.source.as_deref().unwrap(),
        &options(),
    )
}

fn assert_score(report: &FileReport, score: usize) {
    assert!(
        !report.issues.iter().any(|i| i.rule_key == "go:S2260"),
        "{:?}",
        report.issues
    );
    let findings: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.rule_key == "go:S3776")
        .collect();
    if score == 0 {
        assert!(findings.is_empty(), "{findings:?}");
    } else {
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].message,
            format!(
                "Refactor this method to reduce its Cognitive Complexity from {score} to the 0 allowed."
            )
        );
    }
}

fn assert_exempt(target: &str, helper: &str) {
    let members = [
        Member::new("consumer.go", target),
        Member::new("helper.go", helper),
    ];
    let mut expected = local(&members[0]);
    assert_score(&expected, 1);
    expected.issues.retain(|i| i.rule_key != "go:S3776");
    let actual = contextual(&members);
    assert_score(&actual, 0);
    assert_eq!(actual, expected, "all other report fields preserved");
}

fn assert_fallback(members: &[Member]) {
    assert_eq!(
        contextual(members),
        local(&members[0]),
        "{}",
        members[0].source.as_deref().unwrap()
    );
}

#[test]
fn s3776_project_sibling_tuple_errors() {
    assert_exempt(CALLER, HELPER);
    assert_exempt(
        "package sample\nfunc arbitrary() { value, mishap := totallyDifferent(); _ = value; mishap = nil; if mishap != nil { println(mishap) } }\n",
        "package sample\nfunc totallyDifferent() (int,error) { return 0,nil }\n",
    );
    let target = "package sample\nfunc inspect(flag bool) {\n _, problem := supply()\n if problem != nil {\n  if flag { println(problem) }\n }\n if flag { println(flag) }\n}\n";
    let members = [
        Member::new("consumer.go", target),
        Member::new("helper.go", HELPER),
    ];
    let actual = contextual(&members);
    assert_score(&actual, 2);
    let issue = actual
        .issues
        .iter()
        .find(|i| i.rule_key == "go:S3776")
        .unwrap();
    let locations: Vec<_> = issue
        .flows
        .iter()
        .map(|flow| {
            assert_eq!(flow.locations.len(), 1);
            let l = &flow.locations[0];
            assert!(l.path.is_none());
            (
                l.range.start.line,
                l.range.start.column,
                l.range.end.column,
                l.message.as_str(),
            )
        })
        .collect();
    assert_eq!(locations, [(5, 2, 4, "+1"), (7, 1, 3, "+1")]);
    let mut expected = local(&members[0]);
    let finding = expected
        .issues
        .iter_mut()
        .find(|i| i.rule_key == "go:S3776")
        .unwrap();
    "Refactor this method to reduce its Cognitive Complexity from 2 to the 0 allowed."
        .clone_into(&mut finding.message);
    finding
        .flows
        .retain(|flow| flow.locations[0].range.start.line != 4);
    "+1".clone_into(&mut finding.flows[0].locations[0].message);
    assert_eq!(actual, expected);
}

#[test]
fn s3776_project_direct_error_results() {
    assert_exempt(
        "package sample\nfunc inspect(){ problem := supply(); if problem != nil {println(problem)} }\n",
        "package sample\nfunc supply() error {return nil}\n",
    );
    for (bind, name) in [("problem, _, _", "problem"), ("_, problem, _", "problem")] {
        assert_exempt(
            &format!(
                "package sample\nfunc inspect(){{ {bind} := supply(); if {name} != nil {{println({name})}} }}\n"
            ),
            "package sample\nfunc supply() (a,b error,n int) {return nil,nil,0}\n",
        );
    }
    assert_exempt(
        "package sample\nfunc uniqueVars(){ value := supply(); if value != nil {println(value)} }\n",
        "package sample\nfunc supply() (value error) {return nil}\n",
    );
}

#[test]
fn s3776_project_regexp_function_variable() {
    for (alias, variable) in [("regexp", "makePattern"), ("rx", "arbitraryFactory")] {
        let helper = format!(
            "package sample\nimport {alias} \"regexp\"\nvar {variable} = {alias}.Compile\n"
        );
        let caller = format!(
            "package sample\nfunc inspect(){{ _, problem := {variable}(\"x\"); if problem != nil {{println(problem)}} }}\n"
        );
        assert_exempt(&caller, &helper);
    }
    let target = "package sample\nimport rx \"regexp\"\nfunc inspect(){ _, problem := makePattern(\"x\"); if problem != nil {println(problem)} }\n";
    let false_helper = "package sample\nimport rx \"foreign\"\nvar makePattern = rx.Compile\n";
    assert_fallback(&[
        Member::new("consumer.go", target),
        Member::new("helper.go", false_helper),
    ]);
    let wrong_slot = "package sample\nfunc inspect(){ pointer, _ := makePattern(\"x\"); if pointer != nil {println(pointer)} }\n";
    assert_fallback(&[
        Member::new("consumer.go", wrong_slot),
        Member::new(
            "helper.go",
            "package sample\nimport \"regexp\"\nvar makePattern = regexp.Compile\n",
        ),
    ]);
}

#[test]
fn s3776_project_package_namespace_refusals() {
    for (name, helper) in [
        ("/virtual/other/helper.go", HELPER),
        (
            "helper.go",
            "package foreign\nfunc supply() (int,error){return 0,nil}\n",
        ),
        (
            "helper.go",
            "package sample\nfunc supply() (int,error){return 0,nil}\nfunc supply() (int,error){return 0,nil}\n",
        ),
        (
            "helper.go",
            "package sample\nfunc supply() (int,error){return 0,nil}\nvar supply = 1\n",
        ),
        ("helper.go", "package sample\nfunc supply( {\n"),
    ] {
        assert_fallback(&[
            Member::new("consumer.go", CALLER),
            Member::new(name, helper),
        ]);
    }
    let mut members = vec![
        Member::new("consumer.go", CALLER),
        Member::new("helper.go", HELPER),
    ];
    for poison in [
        "package foreign\n",
        "package sample\nvar supply int\n",
        "package sample\nconst supply = 1\n",
        "package sample\ntype supply int\n",
    ] {
        members.push(Member::new("poison.go", poison));
        assert_fallback(&members);
        members.pop();
    }
    let conflict = "package sample\nvar supply = func() (int,*int){return 0,nil}\nfunc inspect(){_,problem:=supply();if problem!=nil{println(problem)}}\n";
    assert_fallback(&[
        Member::new("consumer.go", conflict),
        Member::new("helper.go", HELPER),
    ]);
}

#[test]
fn s3776_project_test_scope_isolation() {
    for (name, classification) in [
        ("custom.go", FileClassification::Test),
        ("helper_test.go", FileClassification::Source),
        ("helper.go", FileClassification::Excluded),
    ] {
        let mut helper = Member::new(name, HELPER);
        helper.classification = classification;
        assert_fallback(&[Member::new("consumer.go", CALLER), helper]);
    }
    assert_exempt(CALLER, HELPER);
    let members = [
        Member::new("consumer.go", CALLER),
        Member::new("test_helpers.go", HELPER),
    ];
    assert_score(&contextual(&members), 0);
    let mut target = Member::new("custom.go", CALLER);
    target.classification = FileClassification::Test;
    assert_fallback(&[target, Member::new("helper.go", HELPER)]);
    assert_fallback(&[
        Member::new("consumer.go", CALLER),
        Member::new(
            "helper.go",
            "package sample_test\nfunc supply()(int,error){return 0,nil}\n",
        ),
    ]);
}

#[test]
fn s3776_project_build_scope_refusals() {
    for (name, prefix) in [
        ("helper.go", "//go:build linux\n\n"),
        ("helper.go", "// +build linux\n\n"),
        ("helper_linux.go", ""),
        ("helper_amd64.go", ""),
        ("helper_linux_amd64.go", ""),
    ] {
        assert_fallback(&[
            Member::new("consumer.go", CALLER),
            Member::new(name, &format!("{prefix}{HELPER}")),
        ]);
    }
    assert_fallback(&[
        Member::new("consumer.go", CALLER),
        Member::new(
            "helper.go",
            &format!(
                "package sample\nimport \"C\"\n{}",
                HELPER.trim_start_matches("package sample\n")
            ),
        ),
    ]);
    let mut unavailable = Member::new("helper.go", HELPER);
    unavailable.physical = None;
    assert_fallback(&[Member::new("consumer.go", CALLER), unavailable]);
    let members = [
        Member::new("consumer.go", CALLER),
        Member::new("helper.go", HELPER),
        Member::new("/virtual/other/poison_linux.go", "package other\n"),
    ];
    assert_score(&contextual(&members), 0);
}

#[test]
fn s3776_project_error_and_local_shadows() {
    for target in [
        "package sample\nfunc inspect(supply func()(int,*int)){ _,problem:=supply(); if problem!=nil{println(problem)} }\n",
        "package sample\nfunc inspect(){ supply:=unknown; _,problem:=supply();if problem!=nil{println(problem)} }\n",
        "package sample\nfunc inspect(){ var supply func()(int,*int); _,problem:=supply();if problem!=nil{println(problem)} }\n",
        "package sample\nfunc inspect(){ type supply int; _,problem:=supply();if problem!=nil{println(problem)} }\n",
        "package sample\nimport supply \"foreign\"\nfunc inspect(){ _,problem:=supply();if problem!=nil{println(problem)} }\n",
        "package sample\nfunc inspect(){type error *int; _,problem:=supply();if problem!=nil{println(problem)} }\n",
        "package sample\nfunc inspect(items []any){for _, supply:=range items{_,problem:=supply();if problem!=nil{println(problem)}}}\n",
        "package sample\nfunc inspect(ch chan any){select{case supply:= <-ch: _,problem:=supply();if problem!=nil{println(problem)}}}\n",
        "package sample\nfunc inspect(x any){switch supply:=x.(type){case int: _,problem:=supply();if problem!=nil{println(problem)}}}\n",
    ] {
        assert_fallback(&[
            Member::new("consumer.go", target),
            Member::new("helper.go", HELPER),
        ]);
    }
    assert_fallback(&[
        Member::new("consumer.go", CALLER),
        Member::new("helper.go", &format!("{HELPER}type error *int\n")),
    ]);
    assert_exempt(
        "package sample\nfunc inspect(){_,problem:=supply();if problem!=nil{println(problem)}; supply:=unknown;_=supply}\n",
        HELPER,
    );
}

#[test]
fn s3776_project_tuple_and_nonerror_negatives() {
    for helper in [
        "package sample\nfunc supply()(int,*error){return 0,nil}\n",
        "package sample\nfunc supply()(error,*int){return nil,nil}\n",
        "package sample\nfunc supply()(int,interface{Error() string}){return 0,nil}\n",
        "package sample\ntype Problem = error\nfunc supply()(int,Problem){return 0,nil}\n",
        "package sample\nfunc supply[T any]()(int,error){return 0,nil}\n",
        "package sample\nimport other \"foreign\"\nvar supply = other.factory\n",
        "package sample\nimport \"regexp\"\nvar first = regexp.Compile\nvar supply = first\n",
    ] {
        assert_fallback(&[
            Member::new("consumer.go", CALLER),
            Member::new("helper.go", helper),
        ]);
    }
    let third =
        "package sample\nfunc inspect(){_,_,problem:=supply();if problem!=nil{println(problem)}}\n";
    assert_fallback(&[
        Member::new("consumer.go", third),
        Member::new("helper.go", HELPER),
    ]);
    let field = "package sample\ntype Router struct{problem error}\nfunc inspect(r Router){if r.problem!=nil{println(r)}}\n";
    assert_fallback(&[
        Member::new("consumer.go", field),
        Member::new("helper.go", HELPER),
    ]);
}

#[test]
fn s3776_project_alias_write_refusals() {
    let target = "package sample\nfunc inspect(){_,problem:=factory(\"x\");if problem!=nil{println(problem)}}\n";
    let declaration = "package sample\nimport rx \"regexp\"\nvar factory = rx.Compile\n";
    assert_exempt(target, declaration);
    for write in [
        "func mutate(){factory=nil}\n",
        "func mutate(){factory=func(string)(*int,error){return nil,nil}}\n",
        "func mutate(){external(&factory)}\n",
        "var escaped = &factory\n",
        "func mutate(){factory:=unknown;_=factory}\n",
        "func mutate(){*(&factory)=unknown}\n",
    ] {
        let members = [
            Member::new("consumer.go", target),
            Member::new("helper.go", declaration),
            Member::new("write.go", &format!("package sample\n{write}")),
        ];
        assert_fallback(&members);
    }
}

#[test]
fn s3776_project_guard_semantics_preserved() {
    for condition in [
        "problem != nil",
        "nil != problem",
        "problem == nil",
        "nil == problem",
        "(problem != nil)",
    ] {
        assert_exempt(
            &format!(
                "package sample\nfunc inspect(){{_,problem:=supply();if {condition} {{println(problem)}}}}\n"
            ),
            HELPER,
        );
    }
    for target in [
        "package sample\nfunc inspect(){_,problem:=supply();if problem!=nil{println(problem)}else{println(0)}}\n",
        "package sample\nfunc inspect(flag bool){_,problem:=supply();if problem!=nil && flag{println(problem)}}\n",
        "package sample\ntype R struct{err error}\nfunc inspect(r R){if r.err!=nil{println(r)}}\n",
    ] {
        assert_fallback(&[
            Member::new("consumer.go", target),
            Member::new("helper.go", HELPER),
        ]);
    }
    let nested = "package sample\nfunc inspect(flag bool){_,problem:=supply();if problem!=nil{if flag{println(problem)}}}\n";
    assert_score(
        &contextual(&[
            Member::new("consumer.go", nested),
            Member::new("helper.go", HELPER),
        ]),
        1,
    );
}

#[test]
fn s3776_project_snapshot_binding_refusals() {
    let members = [
        Member::new("consumer.go", CALLER),
        Member::new("helper.go", HELPER),
    ];
    let index = build(&members);
    for edited in [
        format!("{CALLER}// changed\n"),
        CALLER.replace('\n', "\r\n"),
        CALLER.replace("println(problem)", "println(\"😀\",problem)"),
    ] {
        let target = &members[0];
        assert_eq!(
            analyze_with_project_context(
                target.path.clone(),
                &edited,
                &options(),
                target.identity(),
                &index
            ),
            analyze(target.path.clone(), &edited, &options())
        );
    }
    for mutate in 0..3 {
        let mut target = members[0].clone();
        match mutate {
            0 => target.path = PathBuf::from("/virtual/pkg/renamed.go"),
            1 => target.physical = Some(PathBuf::from("/virtual/else/consumer.go")),
            _ => target.classification = FileClassification::Test,
        }
        assert_eq!(
            analyze_with_project_context(
                target.path.clone(),
                CALLER,
                &options(),
                target.identity(),
                &index
            ),
            local(&target)
        );
    }
    let mut unavailable = members[1].clone();
    unavailable.source = None;
    assert_fallback(&[members[0].clone(), unavailable]);
    let missing = build(&members[1..]);
    assert_eq!(
        analyze_with_project_context(
            members[0].path.clone(),
            CALLER,
            &options(),
            members[0].identity(),
            &missing
        ),
        local(&members[0])
    );
    let projected = [
        members[0].clone(),
        Member::new(
            "helper.go",
            "package sample\nfunc supply()(int,*int){return 0,nil}\n",
        ),
    ];
    assert_ne!(index.digest(), build(&projected).digest());
    assert_fallback(&projected);
}

#[test]
fn s3776_project_no_filesystem_discovery() {
    // These identities deliberately do not exist on disk.
    let members = [
        Member::new("consumer.go", CALLER),
        Member::new("helper.go", HELPER),
    ];
    assert_score(&contextual(&members), 0);
    assert_fallback(&members[..1]);
    let mut excluded = Member::new("poison.go", "package sample\ntype error *int\n");
    excluded.classification = FileClassification::Excluded;
    let members = [members[0].clone(), members[1].clone(), excluded];
    assert_score(&contextual(&members), 0);
}

#[test]
fn s3776_project_context_digest_determinism() {
    let members = [
        Member::new("consumer.go", CALLER),
        Member::new("helper.go", HELPER),
    ];
    let original = build(&members);
    let reversed = build(&[members[1].clone(), members[0].clone()]);
    assert_eq!(original.digest(), reversed.digest());
    assert_eq!(
        analyze_with_project_context(
            members[0].path.clone(),
            CALLER,
            &options(),
            members[0].identity(),
            &original
        ),
        analyze_with_project_context(
            members[0].path.clone(),
            CALLER,
            &options(),
            members[0].identity(),
            &reversed
        )
    );
    let mut duplicate = members[1].clone();
    duplicate.path = PathBuf::from("/virtual/pkg/./helper.go");
    assert_eq!(
        original.digest(),
        build(&[members[0].clone(), members[1].clone(), duplicate]).digest()
    );
    for alteration in 0..5 {
        let mut changed = members[1].clone();
        match alteration {
            0 => changed.source.as_mut().unwrap().push_str("// edit\n"),
            1 => changed.path = PathBuf::from("/virtual/pkg/renamed.go"),
            2 => changed.classification = FileClassification::Test,
            3 => changed.source = None,
            _ => changed.physical = None,
        }
        assert_ne!(
            original.digest(),
            build(&[members[0].clone(), changed]).digest()
        );
    }
    let conflict = Member::new(
        "helper.go",
        "package sample\nfunc supply()(int,*int){return 0,nil}\n",
    );
    assert_fallback(&[members[0].clone(), members[1].clone(), conflict]);
    let mut alias = members[1].clone();
    alias.path = PathBuf::from("/virtual/alias/helper.go");
    assert_fallback(&[members[0].clone(), members[1].clone(), alias]);
    let mut scope_conflict = members[1].clone();
    scope_conflict.classification = FileClassification::Test;
    assert_fallback(&[members[0].clone(), members[1].clone(), scope_conflict]);
}
