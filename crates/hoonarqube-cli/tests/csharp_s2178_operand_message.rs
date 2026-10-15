use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S2178";

// SonarAnalyzer.CSharp 10.33 actual objects and independently frozen whole
// report predictions qualify typed messages; added controls prove preservation.

struct Fixture(PathBuf, String);

impl Fixture {
    fn new(label: &str, filename: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s2178-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("owned fixture directory");
        Self(path, filename.into())
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join(&self.1), source).expect("fixture source");
    }

    fn source(&self) -> Vec<u8> {
        std::fs::read(self.0.join(&self.1)).expect("source readback")
    }

    fn analyze(&self, format: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                &self.1,
                "--profile",
                "sonar-parity",
                "--format",
                format,
                "--cache-dir",
                "cache",
            ])
            .output()
            .expect("actual CLI")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn document(output: &Output, exit: i32) -> Value {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("one complete JSON document")
}

fn targets(report: &Value, format: &str) -> Vec<Value> {
    if format == "json" {
        report["files"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|file| file["issues"].as_array().unwrap())
            .filter(|issue| issue["rule_key"] == KEY)
            .cloned()
            .collect()
    } else {
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|issue| issue["ruleId"] == KEY)
            .cloned()
            .collect()
    }
}

fn inventory(report: &Value, format: &str, filename: &str) {
    assert_eq!(
        report["parity"]["semantic_context"],
        json!({"typescript":"not_applicable","csharp":"missing"})
    );
    assert_eq!(report["parity"]["completeness"], "incomplete");
    assert_eq!(report["parity"]["rule_set_violations"], json!([]));
    assert_eq!(report["parity"]["scope"]["roots"], json!([filename]));
    if format == "json" {
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["files"].as_array().unwrap().len(), 1);
        assert_eq!(report["files"][0]["path"], filename);
        assert_eq!(report["project"]["complete"], true);
        assert_eq!(report["project"]["warnings"], json!([]));
    } else {
        let rules: Vec<_> = report["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        let emitted: BTreeSet<_> = report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["ruleId"].as_str().unwrap())
            .collect();
        assert_eq!(rules, emitted.into_iter().collect::<Vec<_>>());
    }
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), canonical(&object[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn full_document(report: &Value, expected_sha256: &str) -> Option<String> {
    let bytes =
        serde_json::to_vec(&canonical(report)).expect("canonical object keys, preserved arrays");
    let digest = format!("{:x}", Sha256::digest(bytes));
    (digest != expected_sha256)
        .then(|| format!("complete document: expected {expected_sha256}, actual {digest}"))
}

const TYPED: &str = r"namespace S2178ExistingRhsBoundary;
public class Cases
{
    private int calls;
    private bool Next() { calls++; return calls > 0; }
    public bool comparison_eq_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & days == limit) { return true; }
        return false;
    }
    public bool comparison_ne_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & days != limit) { return true; }
        return false;
    }
    public bool comparison_lt_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & days < limit) { return true; }
        return false;
    }
    public bool comparison_le_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & days <= limit) { return true; }
        return false;
    }
    public bool comparison_gt_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & days > limit) { return true; }
        return false;
    }
    public bool comparison_ge_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & days >= limit) { return true; }
        return false;
    }
    public bool logical_and_rhs_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & (HasItems && CanFail)) { return true; }
        return false;
    }
    public bool logical_and_constant_rhs_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & (true && false)) { return true; }
        return false;
    }
    public bool logical_or_rhs_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & (HasItems || CanFail)) { return true; }
        return false;
    }
    public bool logical_or_constant_rhs_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & (true || false)) { return true; }
        return false;
    }
    public bool identifier_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & HasItems) { return true; }
        return false;
    }
    public bool literal_true_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & true) { return true; }
        return false;
    }
    public bool literal_false_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & false) { return true; }
        return false;
    }
    public bool not_identifier_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & !HasItems) { return true; }
        return false;
    }
    public bool not_comparison_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & !(days <= limit)) { return true; }
        return false;
    }
    public bool not_true_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & !true) { return true; }
        return false;
    }
    public bool not_false_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & !false) { return true; }
        return false;
    }
    public bool not_invocation_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & !Next()) { return true; }
        return false;
    }
    public bool constant_le_true_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & 30 <= 31) { return true; }
        return false;
    }
    public bool constant_le_false_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & 32 <= 31) { return true; }
        return false;
    }
    public bool parenthesized_identifier_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & (HasItems)) { return true; }
        return false;
    }
    public bool comparison_eq_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | days == limit) { return true; }
        return false;
    }
    public bool comparison_ne_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | days != limit) { return true; }
        return false;
    }
    public bool comparison_lt_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | days < limit) { return true; }
        return false;
    }
    public bool comparison_le_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | days <= limit) { return true; }
        return false;
    }
    public bool comparison_gt_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | days > limit) { return true; }
        return false;
    }
    public bool comparison_ge_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | days >= limit) { return true; }
        return false;
    }
    public bool logical_and_rhs_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | (HasItems && CanFail)) { return true; }
        return false;
    }
    public bool logical_and_constant_rhs_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | (true && false)) { return true; }
        return false;
    }
    public bool logical_or_rhs_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | (HasItems || CanFail)) { return true; }
        return false;
    }
    public bool logical_or_constant_rhs_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | (true || false)) { return true; }
        return false;
    }
    public bool identifier_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | HasItems) { return true; }
        return false;
    }
    public bool literal_true_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | true) { return true; }
        return false;
    }
    public bool literal_false_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | false) { return true; }
        return false;
    }
    public bool not_identifier_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | !HasItems) { return true; }
        return false;
    }
    public bool not_comparison_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | !(days <= limit)) { return true; }
        return false;
    }
    public bool not_true_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | !true) { return true; }
        return false;
    }
    public bool not_false_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | !false) { return true; }
        return false;
    }
    public bool not_invocation_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | !Next()) { return true; }
        return false;
    }
    public bool constant_le_true_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | 30 <= 31) { return true; }
        return false;
    }
    public bool constant_le_false_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | 32 <= 31) { return true; }
        return false;
    }
    public bool parenthesized_identifier_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | (HasItems)) { return true; }
        return false;
    }
    public bool logical_clean_and(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady && HasItems) { return true; }
        return false;
    }
    public bool logical_clean_or(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady || HasItems) { return true; }
        return false;
    }
    public bool unparenthesized_and_precedence(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady & HasItems && CanFail) { return true; }
        return false;
    }
    public bool unparenthesized_or_precedence(int days, int limit, bool IsReady, bool HasItems, bool CanFail)
    {
        if (IsReady | HasItems || CanFail) { return true; }
        return false;
    }
}
";

const CONTROLS: &str = r#"// Conservative S2178 preservation controls
namespace Control0 {
class C {  bool M(int n) {  if (true & n == 31) return true; return false; } }
}
namespace Control1 {
class C {  bool M(int n) {  if (true | n == 31) return true; return false; } }
}
namespace Control2 {
class C {  bool M(int n) {  if (true & n != 31) return true; return false; } }
}
namespace Control3 {
class C {  bool M(int n) {  if (true | n != 31) return true; return false; } }
}
namespace Control4 {
class C {  bool M(int n) {  if (true & n < 31) return true; return false; } }
}
namespace Control5 {
class C {  bool M(int n) {  if (true | n < 31) return true; return false; } }
}
namespace Control6 {
class C {  bool M(int n) {  if (true & n <= 31) return true; return false; } }
}
namespace Control7 {
class C {  bool M(int n) {  if (true | n <= 31) return true; return false; } }
}
namespace Control8 {
class C {  bool M(int n) {  if (true & n > 31) return true; return false; } }
}
namespace Control9 {
class C {  bool M(int n) {  if (true | n > 31) return true; return false; } }
}
namespace Control10 {
class C {  bool M(int n) {  if (true & n >= 31) return true; return false; } }
}
namespace Control11 {
class C {  bool M(int n) {  if (true | n >= 31) return true; return false; } }
}
namespace Control12 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1L < 2L) return true; return false; } }
}
namespace Control13 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1U < 2U) return true; return false; } }
}
namespace Control14 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1UL < 2UL) return true; return false; } }
}
namespace Control15 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1F < 2F) return true; return false; } }
}
namespace Control16 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1.0 < 2.0) return true; return false; } }
}
namespace Control17 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1M < 2M) return true; return false; } }
}
namespace Control18 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 'a' == 'b') return true; return false; } }
}
namespace Control19 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & "a" == "b") return true; return false; } }
}
namespace Control20 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1 + 2 < 4) return true; return false; } }
}
namespace Control21 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & n + 1 < 4) return true; return false; } }
}
namespace Control22 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & limit < 4) return true; return false; } }
}
namespace Control23 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & Limit < 4) return true; return false; } }
}
namespace Control24 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & E.One == E.Two) return true; return false; } }
}
namespace Control25 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & int.MaxValue > 0) return true; return false; } }
}
namespace Control26 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & !flag) return true; return false; } }
}
namespace Control27 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & nameof(n) == "n") return true; return false; } }
}
namespace Control28 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & (int)n < 4) return true; return false; } }
}
namespace Control29 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & checked(n + 1) < 4) return true; return false; } }
}
namespace Control30 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & unchecked(n + 1) < 4) return true; return false; } }
}
namespace Control31 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & default(int) == 0) return true; return false; } }
}
namespace Control32 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & !true) return true; return false; } }
}
namespace Control33 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & 1 < 2) return true; return false; } }
}
namespace Control34 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & true != false) return true; return false; } }
}
namespace Control35 {
class C { const int Limit = 2; enum E { One, Two } bool M(int n) { const int limit = 2; const bool flag = true; if (true & null == null) return true; return false; } }
}
namespace Control36 {
class C {  bool M() { int seconds = 0, minutes = 1, hours = 2, days = 30; days += 1; if (true & days <= 31) return true; return false; } }
}
namespace Control37 {
class C {  bool M() { int n = 2; if (true & n < 4) return true; return false; } }
}
namespace Control38 {
class C { int Read() { return 2; } bool M() { int n = Read(); n++; if (true & n < 4) return true; return false; } }
}
namespace Control39 {
class C { int Value; bool M() { int n = Value; n = 3; if (true & n < 4) return true; return false; } }
}
namespace Control40 {
class C {  bool M() { bool flag = true; if (true & !flag) return true; return false; } }
}
namespace Control41 {
class C {  bool M(int n = 2) {  if (true & n < 4) return true; return false; } }
}
namespace Control42 {
class C {  bool M(int @value) {  if (true & @value < 4) return true; return false; } }
}
namespace Control43 {
class C {  bool M() { int @value = 2; if (true & @value < 4) return true; return false; } }
}
namespace Control44 {
class C {  bool M(bool flag) {  if (true & flag == false) return true; return false; } }
}
namespace Control45 {
class C {  bool M(int n) {  if (true & !(n < 4)) return true; return false; } }
}
namespace Control46 {
class C {  bool M(bool flag) {  if (true & !flag) return true; return false; } }
}
namespace Control47 {
class C { bool ReadFlag() { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
}
namespace Control48 {
class C { bool @ReadFlag() { return true; } bool M() {  if (true & !@ReadFlag()) return true; return false; } }
}
namespace Control49 {
class C {  bool M(bool IsReady) {  if (true & IsReady) return true; return false; } }
}
namespace Control50 {
class C {  bool M() { const int n = 2; if (true & n < 4) return true; return false; } }
}
namespace Control51 {
class C {  bool M() { const bool flag = true; if (true & !flag) return true; return false; } }
}
namespace Control52 {
class C {  bool M() { var n = 2; if (true & n < 4) return true; return false; } }
}
namespace Control53 {
class C {  bool M(long n) {  if (true & n < 4) return true; return false; } }
}
namespace Control54 {
class C { int n; bool M() {  if (true & n < 4) return true; return false; } }
}
namespace Control55 {
class C { int n; bool M() {  if (true & this.n < 4) return true; return false; } }
}
namespace Control56 {
class C {  bool M() {  if (true & n < 4) return true; return false; } }
}
namespace Control57 {
class C {  bool M(int n) { int n = 2; if (true & n < 4) return true; return false; } }
}
namespace Control58 {
class C {  bool M() { { int n = 2; } if (true & n < 4) return true; return false; } }
}
namespace Control59 {
class C {  bool M(int n) { { int n = 2; } if (true & n < 4) return true; return false; } }
}
namespace Control60 {
class C { bool M() { if (true & n < 4) return true; int n = 2; return false; } }
}
namespace Control61 {
class C { bool M(int n) { if (true & n < 4) return true; const int n = 2; return false; } }
}
namespace Control62 {
class C { bool M() { int n = 2; { if (true & n < 4) return true; } return false; } }
}
namespace Control63 {
class C {  bool M(int n) { System.Func<int> f = () => 2; if (true & n < 4) return true; return false; } }
}
namespace Control64 {
class C {  bool M(int n) { System.Func<int> f = delegate { return 2; }; if (true & n < 4) return true; return false; } }
}
namespace Control65 {
class C {  bool M(int n) { int F() { return 2; } if (true & n < 4) return true; return false; } }
}
namespace Control66 {
class C {  bool M(int n) { for (int i = 0; i < 1; i++) {} if (true & n < 4) return true; return false; } }
}
namespace Control67 {
class C {  bool M(int n) { foreach (int i in new int[0]) {} if (true & n < 4) return true; return false; } }
}
namespace Control68 {
class C {  bool M(int n) { try {} catch (System.Exception e) {} if (true & n < 4) return true; return false; } }
}
namespace Control69 {
class C {  bool M(int n) { switch (n) { case 0: break; } if (true & n < 4) return true; return false; } }
}
namespace Control70 {
class C {  bool M(int n) { int value = n switch { _ => 0 }; if (true & n < 4) return true; return false; } }
}
namespace Control71 {
class C {  bool M(int n) { using (var stream = new System.IO.MemoryStream()) {} if (true & n < 4) return true; return false; } }
}
namespace Control72 {
class C {  bool M(int n) { using var stream = new System.IO.MemoryStream(); if (true & n < 4) return true; return false; } }
}
namespace Control73 {
class C {  bool M(int n) { unsafe { fixed (int* p = new int[1]) {} } if (true & n < 4) return true; return false; } }
}
namespace Control74 {
class C {  bool M(int n) { bool found = new object() is int value; if (true & n < 4) return true; return false; } }
}
namespace Control75 {
class C {  bool M(int n) { int.TryParse("2", out int value); if (true & n < 4) return true; return false; } }
}
namespace Control76 {
class C {  bool M(int n) { var values = from value in new int[0] select value; if (true & n < 4) return true; return false; } }
}
namespace Control77 {
class C { void M(int n) { System.Func<bool> f = () => { if (true & n < 4) return true; return false; }; } }
}
namespace Control78 {
class C { void M(int n) { bool F() { if (true & n < 4) return true; return false; } } }
}
namespace Control79 {
class C { int n; bool P { get { if (true & n < 4) return true; return false; } } }
}
namespace Control80 {
class C { bool ReadFlag() { return true; } bool M(System.Func<bool> ReadFlag) {  if (true & !ReadFlag()) return true; return false; } }
}
namespace Control81 {
class C { bool ReadFlag() { return true; } bool M() { System.Func<bool> ReadFlag = null; if (true & !ReadFlag()) return true; return false; } }
}
namespace Control82 {
class C { bool ReadFlag() { return true; } bool M() { if (true & !ReadFlag()) return true; System.Func<bool> ReadFlag = null; return false; } }
}
namespace Control83 {
class C { bool ReadFlag() { return true; } bool ReadFlag(int n) { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
}
namespace Control84 {
class C { bool ReadFlag() { return true; } bool ReadFlag() { return true; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
}
namespace Control85 {
class C { bool ReadFlag<T>() { return true; } bool M() {  if (true & !ReadFlag<int>()) return true; return false; } }
}
namespace Control86 {
class C { bool ReadFlag() { return true; } bool M() {  if (true & !this.ReadFlag()) return true; return false; } }
}
namespace Control87 {
class C { bool ReadFlag(int n) { return true; } bool M() {  if (true & !ReadFlag(1)) return true; return false; } }
}
namespace Control88 {
class C {  bool M() {  if (true & !ReadFlag()) return true; return false; } }
}
namespace Control89 {
class C { int ReadFlag() { return 1; } bool M() {  if (true & !ReadFlag()) return true; return false; } }
}
namespace Control90 {
class C { bool ReadFlag() { return true; } bool M() { System.Func<int> f = () => 2; if (true & !ReadFlag()) return true; return false; } }
}
namespace Control91 {
class C {  bool M(bool flag) {  if (true & !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!flag) return true; return false; } }
}
namespace Control92 {
class C {  bool M(int n) {  if (true & (n < 4)) return true; return false; } }
}
namespace Control93 {
class C { bool M(bool flag) { if (true && !flag) return true; return false; } }
}
"#;

const CACHE_RUNTIME: &str = r"class C
{
    bool M(int n)
    {
        if (true & n <= 31) return true;
        return false;
    }
}
";

const CACHE_UNKNOWN: &str = r"class C
{
    bool M()
    {
        const int n = 2;
        if (true & n <= 31) return true;
        return false;
    }
}
";

const TYPED_LF_JSON_TARGETS: &str = r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":8,"column":20},"end":{"line":8,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":13,"column":20},"end":{"line":13,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":18,"column":20},"end":{"line":18,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":23,"column":20},"end":{"line":23,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":28,"column":20},"end":{"line":28,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":33,"column":20},"end":{"line":33,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":38,"column":20},"end":{"line":38,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":43,"column":20},"end":{"line":43,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":48,"column":20},"end":{"line":48,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":53,"column":20},"end":{"line":53,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":58,"column":20},"end":{"line":58,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":63,"column":20},"end":{"line":63,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":68,"column":20},"end":{"line":68,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":73,"column":20},"end":{"line":73,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":78,"column":20},"end":{"line":78,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":83,"column":20},"end":{"line":83,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":88,"column":20},"end":{"line":88,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":93,"column":20},"end":{"line":93,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":98,"column":20},"end":{"line":98,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":103,"column":20},"end":{"line":103,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":108,"column":20},"end":{"line":108,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":113,"column":20},"end":{"line":113,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":118,"column":20},"end":{"line":118,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":123,"column":20},"end":{"line":123,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":128,"column":20},"end":{"line":128,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":133,"column":20},"end":{"line":133,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":138,"column":20},"end":{"line":138,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":143,"column":20},"end":{"line":143,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":148,"column":20},"end":{"line":148,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":153,"column":20},"end":{"line":153,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":158,"column":20},"end":{"line":158,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":163,"column":20},"end":{"line":163,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":168,"column":20},"end":{"line":168,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":173,"column":20},"end":{"line":173,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":178,"column":20},"end":{"line":178,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":183,"column":20},"end":{"line":183,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":188,"column":20},"end":{"line":188,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":193,"column":20},"end":{"line":193,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":198,"column":20},"end":{"line":198,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":203,"column":20},"end":{"line":203,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":208,"column":20},"end":{"line":208,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":213,"column":20},"end":{"line":213,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":228,"column":20},"end":{"line":228,"column":21}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":233,"column":20},"end":{"line":233,"column":21}}}]"###;

const TYPED_LF_SONAR_TARGETS: &str = r###"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":8,"startColumn":20,"startLine":8}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":13,"startColumn":20,"startLine":13}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":18,"startColumn":20,"startLine":18}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":23,"startColumn":20,"startLine":23}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":28,"startColumn":20,"startLine":28}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":33,"startColumn":20,"startLine":33}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":38,"startColumn":20,"startLine":38}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":43,"startColumn":20,"startLine":43}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":48,"startColumn":20,"startLine":48}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":53,"startColumn":20,"startLine":53}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":58,"startColumn":20,"startLine":58}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":63,"startColumn":20,"startLine":63}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":68,"startColumn":20,"startLine":68}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":73,"startColumn":20,"startLine":73}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":78,"startColumn":20,"startLine":78}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":83,"startColumn":20,"startLine":83}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":88,"startColumn":20,"startLine":88}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":93,"startColumn":20,"startLine":93}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":98,"startColumn":20,"startLine":98}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":103,"startColumn":20,"startLine":103}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":108,"startColumn":20,"startLine":108}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":113,"startColumn":20,"startLine":113}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":118,"startColumn":20,"startLine":118}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":123,"startColumn":20,"startLine":123}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":128,"startColumn":20,"startLine":128}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":133,"startColumn":20,"startLine":133}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":138,"startColumn":20,"startLine":138}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":143,"startColumn":20,"startLine":143}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":148,"startColumn":20,"startLine":148}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":153,"startColumn":20,"startLine":153}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":158,"startColumn":20,"startLine":158}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":163,"startColumn":20,"startLine":163}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":168,"startColumn":20,"startLine":168}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":173,"startColumn":20,"startLine":173}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":178,"startColumn":20,"startLine":178}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":183,"startColumn":20,"startLine":183}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":188,"startColumn":20,"startLine":188}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":193,"startColumn":20,"startLine":193}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":21,"endLine":198,"startColumn":20,"startLine":198}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":203,"startColumn":20,"startLine":203}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":208,"startColumn":20,"startLine":208}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":213,"startColumn":20,"startLine":213}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":21,"endLine":228,"startColumn":20,"startLine":228}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":21,"endLine":233,"startColumn":20,"startLine":233}},"ruleId":"csharpsquid:S2178"}]"###;

const TYPED_UNICODE_CRLF_JSON_TARGETS: &str = r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":8,"column":33},"end":{"line":8,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":13,"column":33},"end":{"line":13,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":18,"column":33},"end":{"line":18,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":23,"column":33},"end":{"line":23,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":28,"column":33},"end":{"line":28,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":33,"column":33},"end":{"line":33,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":38,"column":33},"end":{"line":38,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":43,"column":33},"end":{"line":43,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":48,"column":33},"end":{"line":48,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":53,"column":33},"end":{"line":53,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":58,"column":33},"end":{"line":58,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":63,"column":33},"end":{"line":63,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":68,"column":33},"end":{"line":68,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":73,"column":33},"end":{"line":73,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":78,"column":33},"end":{"line":78,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":83,"column":33},"end":{"line":83,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":88,"column":33},"end":{"line":88,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":93,"column":33},"end":{"line":93,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":98,"column":33},"end":{"line":98,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":103,"column":33},"end":{"line":103,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":108,"column":33},"end":{"line":108,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":113,"column":33},"end":{"line":113,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":118,"column":33},"end":{"line":118,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":123,"column":33},"end":{"line":123,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":128,"column":33},"end":{"line":128,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":133,"column":33},"end":{"line":133,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":138,"column":33},"end":{"line":138,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":143,"column":33},"end":{"line":143,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":148,"column":33},"end":{"line":148,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":153,"column":33},"end":{"line":153,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":158,"column":33},"end":{"line":158,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":163,"column":33},"end":{"line":163,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":168,"column":33},"end":{"line":168,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":173,"column":33},"end":{"line":173,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":178,"column":33},"end":{"line":178,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":183,"column":33},"end":{"line":183,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":188,"column":33},"end":{"line":188,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":193,"column":33},"end":{"line":193,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":198,"column":33},"end":{"line":198,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":203,"column":33},"end":{"line":203,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":208,"column":33},"end":{"line":208,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":213,"column":33},"end":{"line":213,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":228,"column":33},"end":{"line":228,"column":34}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":233,"column":33},"end":{"line":233,"column":34}}}]"###;

const TYPED_UNICODE_CRLF_SONAR_TARGETS: &str = r###"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":8,"startColumn":34,"startLine":8}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":13,"startColumn":34,"startLine":13}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":18,"startColumn":34,"startLine":18}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":23,"startColumn":34,"startLine":23}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":28,"startColumn":34,"startLine":28}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":33,"startColumn":34,"startLine":33}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":38,"startColumn":34,"startLine":38}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":43,"startColumn":34,"startLine":43}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":48,"startColumn":34,"startLine":48}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":53,"startColumn":34,"startLine":53}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":58,"startColumn":34,"startLine":58}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":63,"startColumn":34,"startLine":63}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":68,"startColumn":34,"startLine":68}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":73,"startColumn":34,"startLine":73}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":78,"startColumn":34,"startLine":78}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":83,"startColumn":34,"startLine":83}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":88,"startColumn":34,"startLine":88}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":93,"startColumn":34,"startLine":93}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":98,"startColumn":34,"startLine":98}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":103,"startColumn":34,"startLine":103}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":108,"startColumn":34,"startLine":108}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":113,"startColumn":34,"startLine":113}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":118,"startColumn":34,"startLine":118}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":123,"startColumn":34,"startLine":123}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":128,"startColumn":34,"startLine":128}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":133,"startColumn":34,"startLine":133}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":138,"startColumn":34,"startLine":138}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":143,"startColumn":34,"startLine":143}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":148,"startColumn":34,"startLine":148}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":153,"startColumn":34,"startLine":153}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":158,"startColumn":34,"startLine":158}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":163,"startColumn":34,"startLine":163}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":168,"startColumn":34,"startLine":168}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":173,"startColumn":34,"startLine":173}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":178,"startColumn":34,"startLine":178}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":183,"startColumn":34,"startLine":183}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":188,"startColumn":34,"startLine":188}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":193,"startColumn":34,"startLine":193}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":35,"endLine":198,"startColumn":34,"startLine":198}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":203,"startColumn":34,"startLine":203}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":208,"startColumn":34,"startLine":208}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":213,"startColumn":34,"startLine":213}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":35,"endLine":228,"startColumn":34,"startLine":228}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"endColumn":35,"endLine":233,"startColumn":34,"startLine":233}},"ruleId":"csharpsquid:S2178"}]"###;

const CONTROLS_LF_JSON_TARGETS: &str = r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":3,"column":37},"end":{"line":3,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":6,"column":37},"end":{"line":6,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":9,"column":37},"end":{"line":9,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":12,"column":37},"end":{"line":12,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":15,"column":37},"end":{"line":15,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":18,"column":37},"end":{"line":18,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":21,"column":37},"end":{"line":21,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":24,"column":37},"end":{"line":24,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":27,"column":37},"end":{"line":27,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":30,"column":37},"end":{"line":30,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":33,"column":37},"end":{"line":33,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":36,"column":37},"end":{"line":36,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":39,"column":121},"end":{"line":39,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":42,"column":121},"end":{"line":42,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":45,"column":121},"end":{"line":45,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":48,"column":121},"end":{"line":48,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":51,"column":121},"end":{"line":51,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":54,"column":121},"end":{"line":54,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":57,"column":121},"end":{"line":57,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":60,"column":121},"end":{"line":60,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":63,"column":121},"end":{"line":63,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":66,"column":121},"end":{"line":66,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":69,"column":121},"end":{"line":69,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":72,"column":121},"end":{"line":72,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":75,"column":121},"end":{"line":75,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":78,"column":121},"end":{"line":78,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":81,"column":121},"end":{"line":81,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":84,"column":121},"end":{"line":84,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":87,"column":121},"end":{"line":87,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":90,"column":121},"end":{"line":90,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":93,"column":121},"end":{"line":93,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":96,"column":121},"end":{"line":96,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":99,"column":121},"end":{"line":99,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":102,"column":121},"end":{"line":102,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":105,"column":121},"end":{"line":105,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":108,"column":121},"end":{"line":108,"column":122}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":111,"column":94},"end":{"line":111,"column":95}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":114,"column":42},"end":{"line":114,"column":43}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":117,"column":76},"end":{"line":117,"column":77}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":120,"column":63},"end":{"line":120,"column":64}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":123,"column":49},"end":{"line":123,"column":50}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":126,"column":41},"end":{"line":126,"column":42}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":129,"column":42},"end":{"line":129,"column":43}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":132,"column":47},"end":{"line":132,"column":48}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":135,"column":41},"end":{"line":135,"column":42}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":138,"column":37},"end":{"line":138,"column":38}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":141,"column":41},"end":{"line":141,"column":42}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":144,"column":64},"end":{"line":144,"column":65}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":147,"column":65},"end":{"line":147,"column":66}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":150,"column":44},"end":{"line":150,"column":45}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":153,"column":48},"end":{"line":153,"column":49}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":156,"column":55},"end":{"line":156,"column":56}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":159,"column":42},"end":{"line":159,"column":43}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":162,"column":38},"end":{"line":162,"column":39}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":165,"column":38},"end":{"line":165,"column":39}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":168,"column":38},"end":{"line":168,"column":39}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":171,"column":32},"end":{"line":171,"column":33}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":174,"column":47},"end":{"line":174,"column":48}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":177,"column":46},"end":{"line":177,"column":47}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":180,"column":51},"end":{"line":180,"column":52}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":183,"column":30},"end":{"line":183,"column":31}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":186,"column":35},"end":{"line":186,"column":36}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":189,"column":43},"end":{"line":189,"column":44}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":192,"column":66},"end":{"line":192,"column":67}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":195,"column":81},"end":{"line":195,"column":82}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":198,"column":58},"end":{"line":198,"column":59}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":201,"column":67},"end":{"line":201,"column":68}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":204,"column":69},"end":{"line":204,"column":70}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":207,"column":73},"end":{"line":207,"column":74}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":210,"column":66},"end":{"line":210,"column":67}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":213,"column":69},"end":{"line":213,"column":70}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":216,"column":89},"end":{"line":216,"column":90}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":219,"column":85},"end":{"line":219,"column":86}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":222,"column":78},"end":{"line":222,"column":79}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":225,"column":76},"end":{"line":225,"column":77}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":228,"column":70},"end":{"line":228,"column":71}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":231,"column":88},"end":{"line":231,"column":89}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":234,"column":65},"end":{"line":234,"column":66}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":237,"column":46},"end":{"line":237,"column":47}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":240,"column":41},"end":{"line":240,"column":42}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":243,"column":90},"end":{"line":243,"column":91}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":246,"column":98},"end":{"line":246,"column":99}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":249,"column":63},"end":{"line":249,"column":64}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":252,"column":102},"end":{"line":252,"column":103}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":255,"column":97},"end":{"line":255,"column":98}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":258,"column":67},"end":{"line":258,"column":68}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":261,"column":64},"end":{"line":261,"column":65}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":264,"column":69},"end":{"line":264,"column":70}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":267,"column":32},"end":{"line":267,"column":33}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":270,"column":60},"end":{"line":270,"column":61}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":273,"column":93},"end":{"line":273,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":276,"column":41},"end":{"line":276,"column":42}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":279,"column":37},"end":{"line":279,"column":38}}}]"###;

const CONTROLS_LF_SONAR_TARGETS: &str = r###"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":3,"startColumn":37,"startLine":3}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":6,"startColumn":37,"startLine":6}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":9,"startColumn":37,"startLine":9}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":12,"startColumn":37,"startLine":12}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":15,"startColumn":37,"startLine":15}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":18,"startColumn":37,"startLine":18}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":21,"startColumn":37,"startLine":21}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":24,"startColumn":37,"startLine":24}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":27,"startColumn":37,"startLine":27}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":30,"startColumn":37,"startLine":30}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":33,"startColumn":37,"startLine":33}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":36,"startColumn":37,"startLine":36}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":39,"startColumn":121,"startLine":39}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":42,"startColumn":121,"startLine":42}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":45,"startColumn":121,"startLine":45}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":48,"startColumn":121,"startLine":48}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":51,"startColumn":121,"startLine":51}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":54,"startColumn":121,"startLine":54}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":57,"startColumn":121,"startLine":57}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":60,"startColumn":121,"startLine":60}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":63,"startColumn":121,"startLine":63}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":66,"startColumn":121,"startLine":66}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":69,"startColumn":121,"startLine":69}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":72,"startColumn":121,"startLine":72}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":75,"startColumn":121,"startLine":75}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":78,"startColumn":121,"startLine":78}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":81,"startColumn":121,"startLine":81}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":84,"startColumn":121,"startLine":84}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":87,"startColumn":121,"startLine":87}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":90,"startColumn":121,"startLine":90}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":93,"startColumn":121,"startLine":93}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":96,"startColumn":121,"startLine":96}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":99,"startColumn":121,"startLine":99}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":102,"startColumn":121,"startLine":102}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":105,"startColumn":121,"startLine":105}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":122,"endLine":108,"startColumn":121,"startLine":108}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":95,"endLine":111,"startColumn":94,"startLine":111}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":43,"endLine":114,"startColumn":42,"startLine":114}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":77,"endLine":117,"startColumn":76,"startLine":117}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":64,"endLine":120,"startColumn":63,"startLine":120}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":50,"endLine":123,"startColumn":49,"startLine":123}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":42,"endLine":126,"startColumn":41,"startLine":126}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":43,"endLine":129,"startColumn":42,"startLine":129}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":48,"endLine":132,"startColumn":47,"startLine":132}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":42,"endLine":135,"startColumn":41,"startLine":135}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":138,"startColumn":37,"startLine":138}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":42,"endLine":141,"startColumn":41,"startLine":141}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":65,"endLine":144,"startColumn":64,"startLine":144}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":66,"endLine":147,"startColumn":65,"startLine":147}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":45,"endLine":150,"startColumn":44,"startLine":150}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":49,"endLine":153,"startColumn":48,"startLine":153}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":56,"endLine":156,"startColumn":55,"startLine":156}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":43,"endLine":159,"startColumn":42,"startLine":159}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":39,"endLine":162,"startColumn":38,"startLine":162}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":39,"endLine":165,"startColumn":38,"startLine":165}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":39,"endLine":168,"startColumn":38,"startLine":168}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":33,"endLine":171,"startColumn":32,"startLine":171}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":48,"endLine":174,"startColumn":47,"startLine":174}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":47,"endLine":177,"startColumn":46,"startLine":177}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":52,"endLine":180,"startColumn":51,"startLine":180}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":31,"endLine":183,"startColumn":30,"startLine":183}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":36,"endLine":186,"startColumn":35,"startLine":186}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":44,"endLine":189,"startColumn":43,"startLine":189}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":67,"endLine":192,"startColumn":66,"startLine":192}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":82,"endLine":195,"startColumn":81,"startLine":195}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":59,"endLine":198,"startColumn":58,"startLine":198}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":68,"endLine":201,"startColumn":67,"startLine":201}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":70,"endLine":204,"startColumn":69,"startLine":204}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":74,"endLine":207,"startColumn":73,"startLine":207}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":67,"endLine":210,"startColumn":66,"startLine":210}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":70,"endLine":213,"startColumn":69,"startLine":213}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":90,"endLine":216,"startColumn":89,"startLine":216}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":86,"endLine":219,"startColumn":85,"startLine":219}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":79,"endLine":222,"startColumn":78,"startLine":222}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":77,"endLine":225,"startColumn":76,"startLine":225}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":71,"endLine":228,"startColumn":70,"startLine":228}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":89,"endLine":231,"startColumn":88,"startLine":231}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":66,"endLine":234,"startColumn":65,"startLine":234}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":47,"endLine":237,"startColumn":46,"startLine":237}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":42,"endLine":240,"startColumn":41,"startLine":240}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":91,"endLine":243,"startColumn":90,"startLine":243}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":99,"endLine":246,"startColumn":98,"startLine":246}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":64,"endLine":249,"startColumn":63,"startLine":249}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":103,"endLine":252,"startColumn":102,"startLine":252}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":98,"endLine":255,"startColumn":97,"startLine":255}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":68,"endLine":258,"startColumn":67,"startLine":258}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":65,"endLine":261,"startColumn":64,"startLine":261}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":70,"endLine":264,"startColumn":69,"startLine":264}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":33,"endLine":267,"startColumn":32,"startLine":267}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":61,"endLine":270,"startColumn":60,"startLine":270}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":94,"endLine":273,"startColumn":93,"startLine":273}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":42,"endLine":276,"startColumn":41,"startLine":276}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":38,"endLine":279,"startColumn":37,"startLine":279}},"ruleId":"csharpsquid:S2178"}]"###;

const CONTROLS_UNICODE_CRLF_JSON_TARGETS: &str = r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":3,"column":50},"end":{"line":3,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":6,"column":50},"end":{"line":6,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":9,"column":50},"end":{"line":9,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":12,"column":50},"end":{"line":12,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":15,"column":50},"end":{"line":15,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":18,"column":50},"end":{"line":18,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":21,"column":50},"end":{"line":21,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":24,"column":50},"end":{"line":24,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":27,"column":50},"end":{"line":27,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":30,"column":50},"end":{"line":30,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":33,"column":50},"end":{"line":33,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":36,"column":50},"end":{"line":36,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":39,"column":134},"end":{"line":39,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":42,"column":134},"end":{"line":42,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":45,"column":134},"end":{"line":45,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":48,"column":134},"end":{"line":48,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":51,"column":134},"end":{"line":51,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":54,"column":134},"end":{"line":54,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":57,"column":134},"end":{"line":57,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":60,"column":134},"end":{"line":60,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":63,"column":134},"end":{"line":63,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":66,"column":134},"end":{"line":66,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":69,"column":134},"end":{"line":69,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":72,"column":134},"end":{"line":72,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":75,"column":134},"end":{"line":75,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":78,"column":134},"end":{"line":78,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":81,"column":134},"end":{"line":81,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":84,"column":134},"end":{"line":84,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":87,"column":134},"end":{"line":87,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":90,"column":134},"end":{"line":90,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":93,"column":134},"end":{"line":93,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":96,"column":134},"end":{"line":96,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":99,"column":134},"end":{"line":99,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":102,"column":134},"end":{"line":102,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":105,"column":134},"end":{"line":105,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":108,"column":134},"end":{"line":108,"column":135}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":111,"column":107},"end":{"line":111,"column":108}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":114,"column":55},"end":{"line":114,"column":56}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":117,"column":89},"end":{"line":117,"column":90}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":120,"column":76},"end":{"line":120,"column":77}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":123,"column":62},"end":{"line":123,"column":63}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":126,"column":54},"end":{"line":126,"column":55}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":129,"column":55},"end":{"line":129,"column":56}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":132,"column":60},"end":{"line":132,"column":61}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":135,"column":54},"end":{"line":135,"column":55}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":138,"column":50},"end":{"line":138,"column":51}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":141,"column":54},"end":{"line":141,"column":55}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":144,"column":77},"end":{"line":144,"column":78}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":147,"column":78},"end":{"line":147,"column":79}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":150,"column":57},"end":{"line":150,"column":58}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":153,"column":61},"end":{"line":153,"column":62}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":156,"column":68},"end":{"line":156,"column":69}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":159,"column":55},"end":{"line":159,"column":56}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":162,"column":51},"end":{"line":162,"column":52}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":165,"column":51},"end":{"line":165,"column":52}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":168,"column":51},"end":{"line":168,"column":52}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":171,"column":45},"end":{"line":171,"column":46}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":174,"column":60},"end":{"line":174,"column":61}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":177,"column":59},"end":{"line":177,"column":60}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":180,"column":64},"end":{"line":180,"column":65}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":183,"column":43},"end":{"line":183,"column":44}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":186,"column":48},"end":{"line":186,"column":49}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":189,"column":56},"end":{"line":189,"column":57}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":192,"column":79},"end":{"line":192,"column":80}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":195,"column":94},"end":{"line":195,"column":95}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":198,"column":71},"end":{"line":198,"column":72}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":201,"column":80},"end":{"line":201,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":204,"column":82},"end":{"line":204,"column":83}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":207,"column":86},"end":{"line":207,"column":87}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":210,"column":79},"end":{"line":210,"column":80}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":213,"column":82},"end":{"line":213,"column":83}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":216,"column":102},"end":{"line":216,"column":103}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":219,"column":98},"end":{"line":219,"column":99}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":222,"column":91},"end":{"line":222,"column":92}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":225,"column":89},"end":{"line":225,"column":90}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":228,"column":83},"end":{"line":228,"column":84}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":231,"column":101},"end":{"line":231,"column":102}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":234,"column":78},"end":{"line":234,"column":79}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":237,"column":59},"end":{"line":237,"column":60}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":240,"column":54},"end":{"line":240,"column":55}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":243,"column":103},"end":{"line":243,"column":104}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":246,"column":111},"end":{"line":246,"column":112}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":249,"column":76},"end":{"line":249,"column":77}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":252,"column":115},"end":{"line":252,"column":116}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":255,"column":110},"end":{"line":255,"column":111}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":258,"column":80},"end":{"line":258,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":261,"column":77},"end":{"line":261,"column":78}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":264,"column":82},"end":{"line":264,"column":83}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":267,"column":45},"end":{"line":267,"column":46}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":270,"column":73},"end":{"line":270,"column":74}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":273,"column":106},"end":{"line":273,"column":107}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":276,"column":54},"end":{"line":276,"column":55}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":279,"column":50},"end":{"line":279,"column":51}}}]"###;

const CONTROLS_UNICODE_CRLF_SONAR_TARGETS: &str = r###"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":3,"startColumn":51,"startLine":3}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":6,"startColumn":51,"startLine":6}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":9,"startColumn":51,"startLine":9}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":12,"startColumn":51,"startLine":12}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":15,"startColumn":51,"startLine":15}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":18,"startColumn":51,"startLine":18}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":21,"startColumn":51,"startLine":21}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":24,"startColumn":51,"startLine":24}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":27,"startColumn":51,"startLine":27}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":30,"startColumn":51,"startLine":30}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":33,"startColumn":51,"startLine":33}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":36,"startColumn":51,"startLine":36}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":39,"startColumn":135,"startLine":39}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":42,"startColumn":135,"startLine":42}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":45,"startColumn":135,"startLine":45}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":48,"startColumn":135,"startLine":48}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":51,"startColumn":135,"startLine":51}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":54,"startColumn":135,"startLine":54}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":57,"startColumn":135,"startLine":57}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":60,"startColumn":135,"startLine":60}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":63,"startColumn":135,"startLine":63}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":66,"startColumn":135,"startLine":66}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":69,"startColumn":135,"startLine":69}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":72,"startColumn":135,"startLine":72}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":75,"startColumn":135,"startLine":75}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":78,"startColumn":135,"startLine":78}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":81,"startColumn":135,"startLine":81}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":84,"startColumn":135,"startLine":84}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":87,"startColumn":135,"startLine":87}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":90,"startColumn":135,"startLine":90}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":93,"startColumn":135,"startLine":93}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":96,"startColumn":135,"startLine":96}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":99,"startColumn":135,"startLine":99}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":102,"startColumn":135,"startLine":102}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":105,"startColumn":135,"startLine":105}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":136,"endLine":108,"startColumn":135,"startLine":108}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":109,"endLine":111,"startColumn":108,"startLine":111}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":57,"endLine":114,"startColumn":56,"startLine":114}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":91,"endLine":117,"startColumn":90,"startLine":117}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":78,"endLine":120,"startColumn":77,"startLine":120}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":64,"endLine":123,"startColumn":63,"startLine":123}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":56,"endLine":126,"startColumn":55,"startLine":126}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":57,"endLine":129,"startColumn":56,"startLine":129}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":62,"endLine":132,"startColumn":61,"startLine":132}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":56,"endLine":135,"startColumn":55,"startLine":135}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":138,"startColumn":51,"startLine":138}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":56,"endLine":141,"startColumn":55,"startLine":141}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":79,"endLine":144,"startColumn":78,"startLine":144}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":80,"endLine":147,"startColumn":79,"startLine":147}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":59,"endLine":150,"startColumn":58,"startLine":150}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":63,"endLine":153,"startColumn":62,"startLine":153}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":70,"endLine":156,"startColumn":69,"startLine":156}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":57,"endLine":159,"startColumn":56,"startLine":159}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":53,"endLine":162,"startColumn":52,"startLine":162}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":53,"endLine":165,"startColumn":52,"startLine":165}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":53,"endLine":168,"startColumn":52,"startLine":168}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":47,"endLine":171,"startColumn":46,"startLine":171}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":62,"endLine":174,"startColumn":61,"startLine":174}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":61,"endLine":177,"startColumn":60,"startLine":177}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":66,"endLine":180,"startColumn":65,"startLine":180}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":45,"endLine":183,"startColumn":44,"startLine":183}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":50,"endLine":186,"startColumn":49,"startLine":186}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":58,"endLine":189,"startColumn":57,"startLine":189}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":81,"endLine":192,"startColumn":80,"startLine":192}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":96,"endLine":195,"startColumn":95,"startLine":195}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":73,"endLine":198,"startColumn":72,"startLine":198}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":82,"endLine":201,"startColumn":81,"startLine":201}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":84,"endLine":204,"startColumn":83,"startLine":204}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":88,"endLine":207,"startColumn":87,"startLine":207}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":81,"endLine":210,"startColumn":80,"startLine":210}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":84,"endLine":213,"startColumn":83,"startLine":213}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":104,"endLine":216,"startColumn":103,"startLine":216}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":100,"endLine":219,"startColumn":99,"startLine":219}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":93,"endLine":222,"startColumn":92,"startLine":222}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":91,"endLine":225,"startColumn":90,"startLine":225}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":85,"endLine":228,"startColumn":84,"startLine":228}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":103,"endLine":231,"startColumn":102,"startLine":231}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":80,"endLine":234,"startColumn":79,"startLine":234}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":61,"endLine":237,"startColumn":60,"startLine":237}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":56,"endLine":240,"startColumn":55,"startLine":240}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":105,"endLine":243,"startColumn":104,"startLine":243}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":113,"endLine":246,"startColumn":112,"startLine":246}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":78,"endLine":249,"startColumn":77,"startLine":249}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":117,"endLine":252,"startColumn":116,"startLine":252}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":112,"endLine":255,"startColumn":111,"startLine":255}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":82,"endLine":258,"startColumn":81,"startLine":258}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":79,"endLine":261,"startColumn":78,"startLine":261}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":84,"endLine":264,"startColumn":83,"startLine":264}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":47,"endLine":267,"startColumn":46,"startLine":267}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":75,"endLine":270,"startColumn":74,"startLine":270}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":108,"endLine":273,"startColumn":107,"startLine":273}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":56,"endLine":276,"startColumn":55,"startLine":276}},"ruleId":"csharpsquid:S2178"},{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":52,"endLine":279,"startColumn":51,"startLine":279}},"ruleId":"csharpsquid:S2178"}]"###;

const CACHE_RUNTIME_JSON_TARGETS: &str = r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":5,"column":17},"end":{"line":5,"column":18}}}]"#;

const CACHE_RUNTIME_SONAR_TARGETS: &str = r#"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"endColumn":18,"endLine":5,"startColumn":17,"startLine":5}},"ruleId":"csharpsquid:S2178"}]"#;

const CACHE_UNKNOWN_JSON_TARGETS: &str = r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":6,"column":17},"end":{"line":6,"column":18}}}]"#;

const CACHE_UNKNOWN_SONAR_TARGETS: &str = r#"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":18,"endLine":6,"startColumn":17,"startLine":6}},"ruleId":"csharpsquid:S2178"}]"#;

fn unicode_crlf(source: &str) -> String {
    source
        .replace("if (", "/* 😀 café */ if (")
        .replace('\n', "\r\n")
}

fn check(label: &str, source: &str, expected_targets: [&str; 2], hashes: [&str; 2]) {
    let fixture = Fixture::new(label, "cases.cs");
    fixture.write(source.as_bytes());
    // Both formats execute before assertions, including the signed red.
    let outputs = [fixture.analyze("json"), fixture.analyze("sonar")];
    let mut failures = Vec::new();
    for (((format, expected), hash), output) in ["json", "sonar"]
        .into_iter()
        .zip(expected_targets)
        .zip(hashes)
        .zip(&outputs)
    {
        assert!(output.stderr.is_empty(), "{output:?}");
        let report = document(output, 0);
        inventory(&report, format, "cases.cs");
        let wanted: Vec<Value> = serde_json::from_str(expected).unwrap();
        let actual = targets(&report, format);
        if actual != wanted {
            failures.push(format!(
                "{format} target mismatch: expected {wanted:?}, actual {actual:?}"
            ));
        }
        if let Some(failure) = full_document(&report, hash) {
            failures.push(format!("{format} {failure}"));
        }
    }
    assert_eq!(fixture.source(), source.as_bytes());
    assert!(
        failures.is_empty(),
        "complete S2178 documents for {label}: {failures:#?}"
    );
}

#[test]
fn csharp_s2178_cli_complete_typed_lf() {
    check(
        "typed-lf",
        TYPED,
        [TYPED_LF_JSON_TARGETS, TYPED_LF_SONAR_TARGETS],
        [
            "6f70b931bab7ac6b452a036744c7aa6c299e64995e3b022d891bac5d96a46694",
            "209ed383233c82e1298f6adcd4883ef693888c32a4dd2895d7c43ae3b804f848",
        ],
    );
}

#[test]
fn csharp_s2178_cli_complete_typed_unicode_crlf() {
    check(
        "typed-unicode-crlf",
        &unicode_crlf(TYPED),
        [
            TYPED_UNICODE_CRLF_JSON_TARGETS,
            TYPED_UNICODE_CRLF_SONAR_TARGETS,
        ],
        [
            "269c881445854fc63e461d49e980d86f2cded9c4ec60a0590ffad257f8e278d3",
            "090ce8d69cde2b81354c6b6c9a7818ba3d8400cbf42b77b443d9e9578af39f0e",
        ],
    );
}

#[test]
fn csharp_s2178_cli_complete_controls_lf() {
    check(
        "controls-lf",
        CONTROLS,
        [CONTROLS_LF_JSON_TARGETS, CONTROLS_LF_SONAR_TARGETS],
        [
            "5de3238917ee94afabde8d0155a8b87d30ca157c2e2f7fbc10227c96d9a4aa8e",
            "a9737bb07caef2f01d63163c23731863146890dfaf783dffb8fc1dee15398239",
        ],
    );
}

#[test]
fn csharp_s2178_cli_complete_controls_unicode_crlf() {
    check(
        "controls-unicode-crlf",
        &unicode_crlf(CONTROLS),
        [
            CONTROLS_UNICODE_CRLF_JSON_TARGETS,
            CONTROLS_UNICODE_CRLF_SONAR_TARGETS,
        ],
        [
            "f249e3b80806d80e6e10716edf43c3063f0c399d6f243c74b2adff260187d9b1",
            "2b233e65b4361f7305b66abbdf479a3ed298717d3b6faa135be4d5a8bfa4d9da",
        ],
    );
}

#[test]
fn csharp_s2178_cli_cache_runtime_unknown_restored_documents() {
    let fixture = Fixture::new("cache", "cases.cs");
    fixture.write(CACHE_RUNTIME.as_bytes());
    let runtime = [fixture.analyze("json"), fixture.analyze("sonar")];
    fixture.write(CACHE_UNKNOWN.as_bytes());
    let unknown = [fixture.analyze("json"), fixture.analyze("sonar")];
    fixture.write(CACHE_RUNTIME.as_bytes());
    let restored = [fixture.analyze("json"), fixture.analyze("sonar")];
    let expected = [
        [CACHE_RUNTIME_JSON_TARGETS, CACHE_RUNTIME_SONAR_TARGETS],
        [CACHE_UNKNOWN_JSON_TARGETS, CACHE_UNKNOWN_SONAR_TARGETS],
    ];
    let hashes = [
        [
            "bfae88c24c362938a6bf3a2c738e74a16eda9b384a2c52ac56a1f509899ea4da",
            "2900a6bb4ee064534dc0d738bffe356afa81ada533d45a7b9300aefe65c5db4e",
        ],
        [
            "db119751d8a24d815968a7689f49c940e5219dbc77e9ba405b7ae7da930be140",
            "afa2993a7694d581e7e8d1043e9e20b25ff99677b6f3d1deae98a934562bacd6",
        ],
    ];
    let mut failures = Vec::new();
    for (index, format) in ["json", "sonar"].into_iter().enumerate() {
        let before = document(&runtime[index], 0);
        let changed = document(&unknown[index], 0);
        assert_eq!(before, document(&restored[index], 0));
        for (state, report) in [&before, &changed].into_iter().enumerate() {
            inventory(report, format, "cases.cs");
            let wanted: Vec<Value> = serde_json::from_str(expected[state][index]).unwrap();
            if targets(report, format) != wanted {
                failures.push(format!("{format} state {state}: target mismatch"));
            }
            if let Some(failure) = full_document(report, hashes[state][index]) {
                failures.push(format!("{format} state {state}: {failure}"));
            }
        }
    }
    assert_eq!(fixture.source(), CACHE_RUNTIME.as_bytes());
    assert!(failures.is_empty(), "cache transitions: {failures:#?}");
}

#[test]
fn csharp_s2178_cli_preserves_malformed_and_invalid_utf8_documents() {
    let fixture = Fixture::new("incomplete", "cases.cs");
    let hashes = [
        [
            "fde05c3d7ff9bfc4921d574a2a64fe81fea49995fe7b6095de9f81b7582421f7",
            "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
        ],
        [
            "3f20deefc0601c387ef933a2ee62ce5f6fae8748606319170c22e19361b09f15",
            "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
        ],
        [
            "fde05c3d7ff9bfc4921d574a2a64fe81fea49995fe7b6095de9f81b7582421f7",
            "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
        ],
        [
            "fde05c3d7ff9bfc4921d574a2a64fe81fea49995fe7b6095de9f81b7582421f7",
            "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
        ],
        [
            "fde05c3d7ff9bfc4921d574a2a64fe81fea49995fe7b6095de9f81b7582421f7",
            "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
        ],
    ];
    let sources = [b"class C { bool M(int n) { if (true & n <= ) return true; } }\n".as_slice(), b"class C {\xff}\n".as_slice(), b"class C { bool ReadFlag() { return true; } bool M() { if (true & !ReadFlag(,)) return true; return false; } }\n".as_slice(), b"class C { bool M(int n) { if (true & n <= (1 + )) return true; return false; } }\n".as_slice(), b"class C { bool M(int n) { if (true & n <= 31) return true; int broken = ; return false; } }\n".as_slice()];
    for (index, source) in sources.into_iter().enumerate() {
        fixture.write(source);
        let outputs = [fixture.analyze("json"), fixture.analyze("sonar")];
        for (format_index, (format, output)) in
            ["json", "sonar"].into_iter().zip(&outputs).enumerate()
        {
            let report = document(output, 2);
            assert_eq!(report["parity"]["completeness"], "incomplete");
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
                assert!(!report["project"]["warnings"].as_array().unwrap().is_empty());
            }
            assert!(
                full_document(&report, hashes[index][format_index]).is_none(),
                "all diagnostics and metadata: {report}"
            );
        }
        assert_eq!(fixture.source(), source);
    }
}

// Flattened params are deliberately outside the bounded binding witness.
const PARAMS_CONTROLS: &[(&str, &str, [&str; 2], [&str; 2])] = &[
    (
        "params-callee-shadow",
        r"class C { bool ReadFlag() { return true; } bool M(params System.Func<bool>[] ReadFlag) { if (true & !ReadFlag()) return true; return false; } }
",
        [
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":98},"end":{"line":1,"column":99}}}]"#,
            r#"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":99,"endLine":1,"startColumn":98,"startLine":1}},"ruleId":"csharpsquid:S2178"}]"#,
        ],
        [
            "1b081356d3a5a8b74c27568b0ab9b994ad83bf98ed485fd7d56a804f79831464",
            "970fa6f6f4f28ea230bbfa6c69d5d33d5f8d02e6295171fb226108da71ae2e19",
        ],
    ),
    (
        "params-runtime-comparison",
        r"class C { bool M(int n, params int[] values) { if (true & n <= 31) return true; return false; } }
",
        [
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":56},"end":{"line":1,"column":57}}}]"#,
            r#"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":57,"endLine":1,"startColumn":56,"startLine":1}},"ruleId":"csharpsquid:S2178"}]"#,
        ],
        [
            "a4b435e86142bacf0a44c6f93d9d4faf28ee32d3c8aa3088aaa369fe82cc662e",
            "eace40d449e7df8beabead1b58fb5c8112d5aed53024139833d9f19378333289",
        ],
    ),
    (
        "params-duplicate-fallback",
        r"class C { bool M(int n, params int[] n) { if (true & n <= 31) return true; return false; } }
",
        [
            r#"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":51},"end":{"line":1,"column":52}}}]"#,
            r#"[{"primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"endColumn":52,"endLine":1,"startColumn":51,"startLine":1}},"ruleId":"csharpsquid:S2178"}]"#,
        ],
        [
            "22d27c06cc0d9f6d24f2678a7615eb1c8e8981aa4b8c4b9145a3f052f6bff464",
            "c23e0af0d4c7449d4a8b7becc69a33597322c2e465277f492256039528563c6a",
        ],
    ),
];

#[test]
fn csharp_s2178_cli_flattened_params_complete_documents() {
    for &(name, source, expected, hashes) in PARAMS_CONTROLS {
        check(name, source, expected, hashes);
    }
}

const NATIVE_LF: &str = r###"// Parenthesis and narrow logical native preservation controls
namespace Wrapper0 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if ((true) & n < 4) return true; return false; } }
}
namespace Wrapper1 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (n < 4)) return true; return false; } }
}
namespace Wrapper2 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (((true)) & ((n < 4))) return true; return false; } }
}
namespace Wrapper3 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if ((IsReady) & ((HasItems))) return true; return false; } }
}
namespace Wrapper4 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (((true)) & ((false))) return true; return false; } }
}
namespace Wrapper5 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper6 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (true && false)) return true; return false; } }
}
namespace Wrapper7 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (false && HasItems)) return true; return false; } }
}
namespace Wrapper8 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (true && HasItems)) return true; return false; } }
}
namespace Wrapper9 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems && false)) return true; return false; } }
}
namespace Wrapper10 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems && true)) return true; return false; } }
}
namespace Wrapper11 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems || CanFail)) return true; return false; } }
}
namespace Wrapper12 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (true || false)) return true; return false; } }
}
namespace Wrapper13 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (false || HasItems)) return true; return false; } }
}
namespace Wrapper14 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (true || HasItems)) return true; return false; } }
}
namespace Wrapper15 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems || false)) return true; return false; } }
}
namespace Wrapper16 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems || true)) return true; return false; } }
}
namespace Wrapper17 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if ((true) | n < 4) return true; return false; } }
}
namespace Wrapper18 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (n < 4)) return true; return false; } }
}
namespace Wrapper19 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (((true)) | ((n < 4))) return true; return false; } }
}
namespace Wrapper20 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if ((IsReady) | ((HasItems))) return true; return false; } }
}
namespace Wrapper21 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (((true)) | ((false))) return true; return false; } }
}
namespace Wrapper22 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper23 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (true && false)) return true; return false; } }
}
namespace Wrapper24 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (false && HasItems)) return true; return false; } }
}
namespace Wrapper25 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (true && HasItems)) return true; return false; } }
}
namespace Wrapper26 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems && false)) return true; return false; } }
}
namespace Wrapper27 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems && true)) return true; return false; } }
}
namespace Wrapper28 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems || CanFail)) return true; return false; } }
}
namespace Wrapper29 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (true || false)) return true; return false; } }
}
namespace Wrapper30 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (false || HasItems)) return true; return false; } }
}
namespace Wrapper31 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (true || HasItems)) return true; return false; } }
}
namespace Wrapper32 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems || false)) return true; return false; } }
}
namespace Wrapper33 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true | (HasItems || true)) return true; return false; } }
}
namespace Wrapper34 {
class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (ReadFlag() && HasItems)) return true; return false; } }
}
namespace Wrapper35 {
class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (n < 4 && HasItems)) return true; return false; } }
}
namespace Wrapper36 {
class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (!HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper37 {
class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((HasItems) && CanFail)) return true; return false; } }
}
namespace Wrapper38 {
class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems && CanFail && IsReady)) return true; return false; } }
}
namespace Wrapper39 {
class C {  bool M(bool HasItems, bool CanFail, params int[] values) {  if (true & (HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper40 {
class C {  bool M(bool HasItems, bool CanFail) { bool HasItems = true; if (true & (HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper41 {
class C {  bool M(bool CanFail) { const bool HasItems = true; if (true & (HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper42 {
class C {  bool M(bool CanFail) { var HasItems = true; if (true & (HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper43 {
class C { bool M(bool CanFail) { if (true & (HasItems && CanFail)) return true; bool HasItems = true; return false; } }
}
namespace Wrapper44 {
class C {  bool M(int HasItems, bool CanFail) {  if (true & (HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper45 {
class C {  bool M(bool HasItems, bool CanFail) { System.Func<bool> f = () => true; if (true & (HasItems && CanFail)) return true; return false; } }
}
namespace Wrapper46 {
class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (ReadFlag())) return true; return false; } }
}
namespace Wrapper47 {
class C { bool ReadFlag() { return true; } bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (!ReadFlag())) return true; return false; } }
}
namespace Wrapper48 {
class C {  bool M(bool flag) {  if (true & (flag)) return true; return false; } }
}
namespace Wrapper49 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((bool)HasItems)) return true; return false; } }
}
namespace Wrapper50 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (n + 1)) return true; return false; } }
}
namespace Wrapper51 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (n & 1)) return true; return false; } }
}
namespace Wrapper52 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  bool value = true & (HasItems && CanFail); return false; } }
}
namespace Wrapper53 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  return true & (HasItems && CanFail); return false; } }
}
namespace Wrapper54 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  while (true & (n < 4)) return true; return false; } }
}
namespace Wrapper55 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  do { n++; } while (true & (n < 4)); return false; } }
}
namespace Wrapper56 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  for (; true & (n < 4);) return true; return false; } }
}
namespace Wrapper57 {
class C { bool M() { if ((true) && (false)) return true; return false; } }
}
namespace Wrapper58 {
class C { void M(bool HasItems, bool CanFail) { System.Func<bool> f = () => { if (true & (HasItems && CanFail)) return true; return false; }; } }
}
namespace Wrapper59 {
class C { void M(bool HasItems, bool CanFail) { bool F() { if (true & (HasItems && CanFail)) return true; return false; } } }
}
namespace Wrapper60 {
class C { bool HasItems, CanFail; bool P { get { if (true & (HasItems && CanFail)) return true; return false; } } }
}
namespace Wrapper61 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (/* note */ HasItems)) return true; return false; } }
}
namespace Wrapper62 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (HasItems /* note */)) return true; return false; } }
}
namespace Wrapper63 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((/* note */ HasItems))) return true; return false; } }
}
namespace Wrapper64 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((false))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
}
namespace Wrapper65 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((n < 4))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
}
namespace Wrapper66 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((false)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
}
namespace Wrapper67 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & (((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((n < 4)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
}
namespace Wrapper68 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((false))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
}
namespace Wrapper69 {
class C {  bool M(bool IsReady, bool HasItems, bool CanFail, int n) {  if (true & ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((n < 4))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) return true; return false; } }
}
"###;
const NATIVE_LF_JSON_TARGETS: &str = r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":3,"column":82},"end":{"line":3,"column":83}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":6,"column":80},"end":{"line":6,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":9,"column":84},"end":{"line":9,"column":85}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":15,"column":84},"end":{"line":15,"column":85}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":18,"column":80},"end":{"line":18,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":21,"column":80},"end":{"line":21,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":24,"column":80},"end":{"line":24,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":27,"column":80},"end":{"line":27,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":30,"column":80},"end":{"line":30,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":33,"column":80},"end":{"line":33,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":36,"column":80},"end":{"line":36,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":39,"column":80},"end":{"line":39,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":42,"column":80},"end":{"line":42,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":45,"column":80},"end":{"line":45,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":48,"column":80},"end":{"line":48,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":51,"column":80},"end":{"line":51,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":54,"column":82},"end":{"line":54,"column":83}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":57,"column":80},"end":{"line":57,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":60,"column":84},"end":{"line":60,"column":85}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":63,"column":85},"end":{"line":63,"column":86}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":66,"column":84},"end":{"line":66,"column":85}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":69,"column":80},"end":{"line":69,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":72,"column":80},"end":{"line":72,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":75,"column":80},"end":{"line":75,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":78,"column":80},"end":{"line":78,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":81,"column":80},"end":{"line":81,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":84,"column":80},"end":{"line":84,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":87,"column":80},"end":{"line":87,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":90,"column":80},"end":{"line":90,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":93,"column":80},"end":{"line":93,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":96,"column":80},"end":{"line":96,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":99,"column":80},"end":{"line":99,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":102,"column":80},"end":{"line":102,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":105,"column":112},"end":{"line":105,"column":113}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":108,"column":112},"end":{"line":108,"column":113}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":111,"column":112},"end":{"line":111,"column":113}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":117,"column":112},"end":{"line":117,"column":113}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":120,"column":80},"end":{"line":120,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":123,"column":80},"end":{"line":123,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":126,"column":71},"end":{"line":126,"column":72}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":129,"column":64},"end":{"line":129,"column":65}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":132,"column":42},"end":{"line":132,"column":43}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":135,"column":58},"end":{"line":135,"column":59}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":138,"column":92},"end":{"line":138,"column":93}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":144,"column":112},"end":{"line":144,"column":113}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":165,"column":83},"end":{"line":165,"column":84}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":168,"column":95},"end":{"line":168,"column":96}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":171,"column":83},"end":{"line":171,"column":84}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":177,"column":87},"end":{"line":177,"column":88}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":180,"column":68},"end":{"line":180,"column":69}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":183,"column":58},"end":{"line":183,"column":59}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":195,"column":80},"end":{"line":195,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":198,"column":80},"end":{"line":198,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":201,"column":80},"end":{"line":201,"column":81}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":204,"column":80},"end":{"line":204,"column":81}}}]"###;
const NATIVE_LF_SONAR_TARGETS: &str = r###"[{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":3,"endLine":3,"startColumn":82,"endColumn":83}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":6,"endLine":6,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":9,"endLine":9,"startColumn":84,"endColumn":85}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":15,"endLine":15,"startColumn":84,"endColumn":85}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":18,"endLine":18,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":21,"endLine":21,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":24,"endLine":24,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":27,"endLine":27,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":30,"endLine":30,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":33,"endLine":33,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":36,"endLine":36,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":39,"endLine":39,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":42,"endLine":42,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":45,"endLine":45,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":48,"endLine":48,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":51,"endLine":51,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":54,"endLine":54,"startColumn":82,"endColumn":83}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":57,"endLine":57,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":60,"endLine":60,"startColumn":84,"endColumn":85}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":63,"endLine":63,"startColumn":85,"endColumn":86}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":66,"endLine":66,"startColumn":84,"endColumn":85}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":69,"endLine":69,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":72,"endLine":72,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":75,"endLine":75,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":78,"endLine":78,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":81,"endLine":81,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":84,"endLine":84,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":87,"endLine":87,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":90,"endLine":90,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":93,"endLine":93,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":96,"endLine":96,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":99,"endLine":99,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":102,"endLine":102,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":105,"endLine":105,"startColumn":112,"endColumn":113}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":108,"endLine":108,"startColumn":112,"endColumn":113}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":111,"endLine":111,"startColumn":112,"endColumn":113}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":117,"endLine":117,"startColumn":112,"endColumn":113}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":120,"endLine":120,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":123,"endLine":123,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":126,"endLine":126,"startColumn":71,"endColumn":72}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":129,"endLine":129,"startColumn":64,"endColumn":65}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":132,"endLine":132,"startColumn":42,"endColumn":43}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":135,"endLine":135,"startColumn":58,"endColumn":59}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":138,"endLine":138,"startColumn":92,"endColumn":93}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":144,"endLine":144,"startColumn":112,"endColumn":113}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":165,"endLine":165,"startColumn":83,"endColumn":84}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":168,"endLine":168,"startColumn":95,"endColumn":96}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":171,"endLine":171,"startColumn":83,"endColumn":84}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":177,"endLine":177,"startColumn":87,"endColumn":88}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":180,"endLine":180,"startColumn":68,"endColumn":69}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":183,"endLine":183,"startColumn":58,"endColumn":59}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":195,"endLine":195,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":198,"endLine":198,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":201,"endLine":201,"startColumn":80,"endColumn":81}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":204,"endLine":204,"startColumn":80,"endColumn":81}}}]"###;
const NATIVE_UNICODE_CRLF_JSON_TARGETS: &str = r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":3,"column":95},"end":{"line":3,"column":96}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":6,"column":93},"end":{"line":6,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":9,"column":97},"end":{"line":9,"column":98}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":15,"column":97},"end":{"line":15,"column":98}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":18,"column":93},"end":{"line":18,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":21,"column":93},"end":{"line":21,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":24,"column":93},"end":{"line":24,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":27,"column":93},"end":{"line":27,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":30,"column":93},"end":{"line":30,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":33,"column":93},"end":{"line":33,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":36,"column":93},"end":{"line":36,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":39,"column":93},"end":{"line":39,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":42,"column":93},"end":{"line":42,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":45,"column":93},"end":{"line":45,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":48,"column":93},"end":{"line":48,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":51,"column":93},"end":{"line":51,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":54,"column":95},"end":{"line":54,"column":96}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":57,"column":93},"end":{"line":57,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":60,"column":97},"end":{"line":60,"column":98}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":63,"column":98},"end":{"line":63,"column":99}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":66,"column":97},"end":{"line":66,"column":98}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":69,"column":93},"end":{"line":69,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":72,"column":93},"end":{"line":72,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":75,"column":93},"end":{"line":75,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":78,"column":93},"end":{"line":78,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":81,"column":93},"end":{"line":81,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":84,"column":93},"end":{"line":84,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":87,"column":93},"end":{"line":87,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":90,"column":93},"end":{"line":90,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":93,"column":93},"end":{"line":93,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":96,"column":93},"end":{"line":96,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":99,"column":93},"end":{"line":99,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '|' to '||'.","range":{"start":{"line":102,"column":93},"end":{"line":102,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":105,"column":125},"end":{"line":105,"column":126}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":108,"column":125},"end":{"line":108,"column":126}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":111,"column":125},"end":{"line":111,"column":126}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":117,"column":125},"end":{"line":117,"column":126}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":120,"column":93},"end":{"line":120,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":123,"column":93},"end":{"line":123,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":126,"column":84},"end":{"line":126,"column":85}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":129,"column":77},"end":{"line":129,"column":78}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":132,"column":55},"end":{"line":132,"column":56}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":135,"column":71},"end":{"line":135,"column":72}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":138,"column":105},"end":{"line":138,"column":106}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":144,"column":125},"end":{"line":144,"column":126}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":165,"column":83},"end":{"line":165,"column":84}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":168,"column":95},"end":{"line":168,"column":96}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":171,"column":83},"end":{"line":171,"column":84}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":177,"column":100},"end":{"line":177,"column":101}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":180,"column":81},"end":{"line":180,"column":82}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":183,"column":71},"end":{"line":183,"column":72}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":195,"column":93},"end":{"line":195,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":198,"column":93},"end":{"line":198,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":201,"column":93},"end":{"line":201,"column":94}}},{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":204,"column":93},"end":{"line":204,"column":94}}}]"###;
const NATIVE_UNICODE_CRLF_SONAR_TARGETS: &str = r###"[{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":3,"endLine":3,"startColumn":96,"endColumn":97}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":6,"endLine":6,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":9,"endLine":9,"startColumn":98,"endColumn":99}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":15,"endLine":15,"startColumn":98,"endColumn":99}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":18,"endLine":18,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":21,"endLine":21,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":24,"endLine":24,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":27,"endLine":27,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":30,"endLine":30,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":33,"endLine":33,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":36,"endLine":36,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":39,"endLine":39,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":42,"endLine":42,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":45,"endLine":45,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":48,"endLine":48,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":51,"endLine":51,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":54,"endLine":54,"startColumn":96,"endColumn":97}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":57,"endLine":57,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":60,"endLine":60,"startColumn":98,"endColumn":99}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":63,"endLine":63,"startColumn":99,"endColumn":100}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":66,"endLine":66,"startColumn":98,"endColumn":99}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":69,"endLine":69,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":72,"endLine":72,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":75,"endLine":75,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":78,"endLine":78,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":81,"endLine":81,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":84,"endLine":84,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":87,"endLine":87,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":90,"endLine":90,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":93,"endLine":93,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":96,"endLine":96,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":99,"endLine":99,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '|' to '||'.","textRange":{"startLine":102,"endLine":102,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":105,"endLine":105,"startColumn":126,"endColumn":127}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":108,"endLine":108,"startColumn":126,"endColumn":127}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":111,"endLine":111,"startColumn":126,"endColumn":127}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":117,"endLine":117,"startColumn":126,"endColumn":127}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":120,"endLine":120,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":123,"endLine":123,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":126,"endLine":126,"startColumn":85,"endColumn":86}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":129,"endLine":129,"startColumn":78,"endColumn":79}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":132,"endLine":132,"startColumn":56,"endColumn":57}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":135,"endLine":135,"startColumn":72,"endColumn":73}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":138,"endLine":138,"startColumn":106,"endColumn":107}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":144,"endLine":144,"startColumn":126,"endColumn":127}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":165,"endLine":165,"startColumn":83,"endColumn":84}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":168,"endLine":168,"startColumn":95,"endColumn":96}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":171,"endLine":171,"startColumn":83,"endColumn":84}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":177,"endLine":177,"startColumn":101,"endColumn":102}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":180,"endLine":180,"startColumn":82,"endColumn":83}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":183,"endLine":183,"startColumn":72,"endColumn":73}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":195,"endLine":195,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":198,"endLine":198,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":201,"endLine":201,"startColumn":94,"endColumn":95}}},{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":204,"endLine":204,"startColumn":94,"endColumn":95}}}]"###;

const LOGICAL_CACHE_RUNTIME: &str = r###"class C { bool M(bool HasItems, bool CanFail) { if (true & (HasItems && CanFail)) return true; return false; } }
"###;
const LOGICAL_CACHE_RUNTIME_JSON_TARGETS: &str = r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","range":{"start":{"line":1,"column":57},"end":{"line":1,"column":58}}}]"###;
const LOGICAL_CACHE_RUNTIME_SONAR_TARGETS: &str = r###"[{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&' and extract the right operand to a variable if it should always be evaluated.","textRange":{"startLine":1,"endLine":1,"startColumn":57,"endColumn":58}}}]"###;

const LOGICAL_CACHE_UNKNOWN: &str = r###"class C { bool M(bool HasItems, bool CanFail) { if (true & (false && CanFail)) return true; return false; } }
"###;
const LOGICAL_CACHE_UNKNOWN_JSON_TARGETS: &str = r###"[{"rule_key":"csharpsquid:S2178","message":"Correct this '&' to '&&'.","range":{"start":{"line":1,"column":57},"end":{"line":1,"column":58}}}]"###;
const LOGICAL_CACHE_UNKNOWN_SONAR_TARGETS: &str = r###"[{"ruleId":"csharpsquid:S2178","primaryLocation":{"filePath":"cases.cs","message":"Correct this '&' to '&&'.","textRange":{"startLine":1,"endLine":1,"startColumn":57,"endColumn":58}}}]"###;

#[test]
fn csharp_s2178_cli_parenthesized_complete_native_lf() {
    check(
        "native-lf",
        NATIVE_LF,
        [NATIVE_LF_JSON_TARGETS, NATIVE_LF_SONAR_TARGETS],
        [
            "94f30bb2698a0b77c454189878ad8862bcd27dff765a3ecd5cfb9fcb70ba16ef",
            "c56b1be47c54a32da1364a698cb5e6bca8a350069137de1298e5d1e3c6690524",
        ],
    );
}

#[test]
fn csharp_s2178_cli_parenthesized_complete_native_unicode_crlf() {
    check(
        "native-unicode-crlf",
        &unicode_crlf(NATIVE_LF),
        [
            NATIVE_UNICODE_CRLF_JSON_TARGETS,
            NATIVE_UNICODE_CRLF_SONAR_TARGETS,
        ],
        [
            "105ed2c8336a94ca27fd1b670db48a5fab06babd3b53b81aa10472f2007bdc9f",
            "b38275ce1d7ed455527f9cf70739a3b5ffab383abdd7d12f02e4fb145ae67fd2",
        ],
    );
}

#[test]
fn csharp_s2178_cli_parenthesized_malformed_documents() {
    let cases: &[(&str, [&str; 2])] = &[
        (
            r###"class C { bool M(bool HasItems) { if (true & (HasItems false)) return true; return false; } }
"###,
            [
                "fde05c3d7ff9bfc4921d574a2a64fe81fea49995fe7b6095de9f81b7582421f7",
                "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
            ],
        ),
        (
            r###"class C { bool M() { if (true & ()) return true; return false; } }
"###,
            [
                "fde05c3d7ff9bfc4921d574a2a64fe81fea49995fe7b6095de9f81b7582421f7",
                "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
            ],
        ),
        (
            r###"class C { bool M(int n) { if (true & (n < )) return true; return false; } }
"###,
            [
                "fde05c3d7ff9bfc4921d574a2a64fe81fea49995fe7b6095de9f81b7582421f7",
                "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
            ],
        ),
        (
            r###"class C { bool M(int n) { if (true & (n < 4)) return true; int broken = ; return false; } }
"###,
            [
                "fde05c3d7ff9bfc4921d574a2a64fe81fea49995fe7b6095de9f81b7582421f7",
                "09f0c97fa2cbaa07b059bf0d99f43d56e9f2459ce2721585626fe2eb867808a2",
            ],
        ),
    ];
    let mut failures = Vec::new();
    for (source, hashes) in cases {
        let fixture = Fixture::new("wrapper-error", "cases.cs");
        fixture.write(source.as_bytes());
        let outputs = [fixture.analyze("json"), fixture.analyze("sonar")];
        for ((format, output), hash) in ["json", "sonar"].into_iter().zip(&outputs).zip(hashes) {
            let report = document(output, 2);
            assert_eq!(report["parity"]["completeness"], "incomplete");
            assert!(targets(&report, format).is_empty());
            if let Some(failure) = full_document(&report, hash) {
                failures.push(format!("{format}: {failure}"));
            }
        }
        assert_eq!(fixture.source(), source.as_bytes());
    }
    assert!(
        failures.is_empty(),
        "malformed wrapper documents: {failures:#?}"
    );
}

#[test]
fn csharp_s2178_cli_logical_cache_runtime_mixed_restored_documents() {
    let fixture = Fixture::new("logical-cache", "cases.cs");
    let mut reports = Vec::new();
    for source in [
        LOGICAL_CACHE_RUNTIME,
        LOGICAL_CACHE_UNKNOWN,
        LOGICAL_CACHE_RUNTIME,
    ] {
        fixture.write(source.as_bytes());
        let mut phase = Vec::new();
        for format in ["json", "sonar"] {
            assert_eq!(fixture.source(), source.as_bytes());
            phase.push(fixture.analyze(format));
            assert_eq!(fixture.source(), source.as_bytes());
        }
        reports.push(phase);
    }
    let expected = [
        [
            LOGICAL_CACHE_RUNTIME_JSON_TARGETS,
            LOGICAL_CACHE_RUNTIME_SONAR_TARGETS,
        ],
        [
            LOGICAL_CACHE_UNKNOWN_JSON_TARGETS,
            LOGICAL_CACHE_UNKNOWN_SONAR_TARGETS,
        ],
    ];
    let hashes = [
        [
            "8e3487729e49906693ba663699200270de0e724ee8c87b1f8cbc0cdf54fe170d",
            "767bd440f506be8c307e89667305310af76962fe9ce4f18c8907ee3d065ad4e1",
        ],
        [
            "de03126f5d0f0a377be732d62a7d11fd7082eab4631542e0bc8f61c881ca2f60",
            "85c2dc52460347d9e7e0ba9ff08897646123ae2fd5873069d265e5aeaff81702",
        ],
    ];
    let mut failures = Vec::new();
    for (phase, outputs) in reports.iter().enumerate() {
        let state = usize::from(phase == 1);
        for (index, (format, output)) in ["json", "sonar"].into_iter().zip(outputs).enumerate() {
            assert!(output.stderr.is_empty(), "{output:?}");
            let report = document(output, 0);
            inventory(&report, format, "cases.cs");
            let wanted: Vec<Value> = serde_json::from_str(expected[state][index]).unwrap();
            if targets(&report, format) != wanted {
                failures.push(format!("phase {phase} {format} target mismatch"));
            }
            if let Some(failure) = full_document(&report, hashes[state][index]) {
                failures.push(format!("phase {phase} {format}: {failure}"));
            }
            if phase == 2 {
                assert_eq!(report, document(&reports[0][index], 0));
            }
        }
    }
    assert_eq!(fixture.source(), LOGICAL_CACHE_RUNTIME.as_bytes());
    assert!(
        failures.is_empty(),
        "logical same-path cache transition: {failures:#?}"
    );
}
