//! Test suite part; the full suite spans `tests/*.rs`.

use super::*;

#[test]
fn s4792_flags_logger_configuration_writes_and_calls() {
    let violating = analyze_default(
        "LogManager.Configuration = Load();\nXmlConfigurator.Configure(source);\nvar current = LogManager.Configuration;\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S4792");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 2);

    let clean = analyze_default("logger.Info(\"started\");\n");
    assert!(with_key(&clean, "csharpsquid:S4792").is_empty());
}

#[test]
fn s5344_flags_weak_pbkdf2_configuration() {
    let violating = analyze_default(
        "class Repo\n{\n    void Store(string password, byte[] salt)\n    {\n        var defaults = new Rfc2898DeriveBytes(password, salt);\n        var weak = new Rfc2898DeriveBytes(password, salt, 10_000, HashAlgorithmName.SHA1);\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S5344");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);

    let unrelated_hash = analyze_default(
        "class Safe\n{\n    void Hash(byte[] salted)\n    {\n        var sha = SHA256.Create();\n        sha.ComputeHash(salted);\n    }\n}\n",
    );
    assert!(with_key(&unrelated_hash, "csharpsquid:S5344").is_empty());

    let strong_kdf = analyze_default(
        "class Kdf\n{\n    void Derive(string password, byte[] salt)\n    {\n        var derive = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);\n    }\n}\n",
    );
    assert!(with_key(&strong_kdf, "csharpsquid:S5344").is_empty());
}

#[test]
fn s3610_flags_null_comparisons_on_non_nullable_values() {
    let violating = analyze_default(
        "void Check(int? total)\n{\n    bool gone = total.GetType() == typeof(int?);\n    bool older = total.GetType() != typeof(int?);\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3610");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 4);

    let clean = analyze_default(
        "void Fine(int? maybe)\n{\n    if (maybe == null)\n    {\n    }\n    bool type = maybe.GetType() == typeof(int);\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3610").is_empty());
}

#[test]
fn s2995_flags_reference_equals_on_value_types() {
    let violating = analyze_default(
        "struct Point\n{\n    public int X;\n}\nclass C\n{\n}\nvoid Compare(Point a, Point b)\n{\n    var structSame = ReferenceEquals(a, b);\n    var lit = ReferenceEquals(5, a);\n    var refs = ReferenceEquals(r1, r2);\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2995");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 10);
    assert_eq!(flagged[1].range.start.line, 11);

    let clean = analyze_default(
        "class C\n{\n}\nvoid RefCompare(C r1, C r2)\n{\n    var same = ReferenceEquals(r1, r2);\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2995").is_empty());
}

#[test]
fn s3909_flags_legacy_non_generic_collections() {
    let violating =
        analyze_default("public class Legacy : System.Collections.CollectionBase\n{\n}\n");
    let flagged = with_key(&violating, "csharpsquid:S3909");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    let clean = analyze_default(
        "public class Modern : System.Collections.ObjectModel.Collection<int>\n{\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3909").is_empty());
}

#[test]
fn s2387_flags_fields_shadowing_base_fields() {
    let violating = analyze_default(
        "class Base\n{\n    protected int Count;\n}\nclass Derived : Base\n{\n    protected int Count;\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2387");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class Base2\n{\n    protected int Total;\n}\nclass Child2 : Base2\n{\n    protected int Count;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2387").is_empty());
}

#[test]
fn s4025_flags_field_capitalization_collisions() {
    let violating = analyze_default(
        "class Base\n{\n    protected int count;\n}\nclass Derived : Base\n{\n    protected int Count;\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S4025");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class Base2\n{\n    protected int Total;\n}\nclass Child2 : Base2\n{\n    protected int Count;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4025").is_empty());
}

#[test]
fn s1006_flags_override_default_value_drift() {
    let violating = analyze_default(
        "class Greeter\n{\n    public virtual void Greet(string name = \"world\") { }\n}\nclass LoudGreeter : Greeter\n{\n    public override void Greet(string name = \"hi\") { }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S1006");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class Greeter\n{\n    public virtual void Greet(string name = \"world\") { }\n}\nclass SameGreeter : Greeter\n{\n    public override void Greet(string name = \"world\") { }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1006").is_empty());
}

#[test]
fn s1939_flags_redundant_inheritance_entries() {
    let duplicated = analyze_default("class Dup : Exception, System.Exception\n{\n}\n");
    let flagged = with_key(&duplicated, "csharpsquid:S1939");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    let self_named = analyze_default("class Echo : Echo\n{\n}\n");
    assert_eq!(with_key(&self_named, "csharpsquid:S1939").len(), 1);

    let clean = analyze_default("class Ok : Exception\n{\n}\n");
    assert!(with_key(&clean, "csharpsquid:S1939").is_empty());
}

#[test]
fn s3464_flags_inheritance_cycles() {
    let violating = analyze_default("class A : B\n{\n}\nclass B : C\n{\n}\nclass C : A\n{\n}\n");
    let flagged = with_key(&violating, "csharpsquid:S3464");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 4);
    assert_eq!(flagged[2].range.start.line, 7);

    let clean = analyze_default("class P : Q\n{\n}\nclass Q\n{\n}\n");
    assert!(with_key(&clean, "csharpsquid:S3464").is_empty());
}

#[test]
fn s3262_flags_overrides_dropping_params() {
    let violating = analyze_default(
        "class Runner\n{\n    public virtual void Run(params int[] ids) { }\n}\nclass FastRunner : Runner\n{\n    public override void Run(int[] ids) { }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3262");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class Walker\n{\n    public virtual void Walk(params int[] steps) { }\n}\nclass SteadyWalker : Walker\n{\n    public override void Walk(params int[] steps) { }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3262").is_empty());
}

#[test]
fn s3600_flags_overrides_introducing_params() {
    let violating = analyze_default(
        "class Walker\n{\n    public virtual void Walk(int[] steps) { }\n}\nclass SlowWalker : Walker\n{\n    public override void Walk(params int[] steps) { }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3600");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class Mover\n{\n    public virtual void Move(params int[] targets) { }\n}\nclass QuickMover : Mover\n{\n    public override void Move(params int[] targets) { }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3600").is_empty());
}

#[test]
fn s3466_flags_optional_arguments_forwarded_to_base() {
    let violating = analyze_default(
        "class Base\n{\n    public virtual void Save(int retries = 3) { }\n}\nclass Sub : Base\n{\n    public void Retry(int retries = 3)\n    {\n        base.Save();\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3466");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 9);

    let clean = analyze_default(
        "class Base\n{\n    public virtual void Save(int retries = 3) { }\n}\nclass Sub : Base\n{\n    public void Retry(int retries = 3)\n    {\n        base.Save(retries);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3466").is_empty());
}

#[test]
fn s4015_flags_private_members_hiding_public_base_members() {
    let violating = analyze_default(
        "class Base\n{\n    public void Go() { }\n}\nclass Sub : Base\n{\n    private void Go() { }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S4015");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class Base\n{\n    public void Go() { }\n}\nclass Sub : Base\n{\n    public void Go() { }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4015").is_empty());
}

#[test]
fn s4019_flags_methods_hiding_base_without_new() {
    let violating = analyze_default(
        "class Base\n{\n    public void Run() { }\n}\nclass Sub : Base\n{\n    public void Run() { }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S4019");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class Base\n{\n    public void Run() { }\n}\nclass Sub : Base\n{\n    public new void Run() { }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4019").is_empty());
}

#[test]
fn s3444_flags_ambiguous_inherited_interface_members() {
    let violating = analyze_default(
        "interface IA\n{\n    void Show();\n}\ninterface IB\n{\n    void Show();\n}\ninterface IC : IA, IB\n{\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3444");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 9);

    let clean = analyze_default(
        "interface IA\n{\n    void Show();\n}\ninterface IB\n{\n    void Hide();\n}\ninterface IC : IA, IB\n{\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3444").is_empty());
}

#[test]
fn s927_flags_parameter_name_drift_from_base() {
    let violating = analyze_default(
        "class Base\n{\n    public virtual void Move(int distance) { }\n}\nclass Sub : Base\n{\n    public override void Move(int meters) { }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S927");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class Base\n{\n    public virtual void Move(int distance) { }\n}\nclass Sub : Base\n{\n    public override void Move(int distance) { }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S927").is_empty());
}

#[test]
fn s1698_flags_equality_on_equals_overriders() {
    let violating = analyze_default(
        "class Money\n{\n    public override bool Equals(object other)\n    {\n        return true;\n    }\n}\nvoid Check(Money left, Money right)\n{\n    var eq = left == right;\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S1698");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 10);

    let clean = analyze_default(
        "class Plain\n{\n}\nvoid Check(int first, int second)\n{\n    var eq = first == second;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1698").is_empty());
}

#[test]
fn s2330_flags_array_covariance_assignments() {
    let violating = analyze_default(
        "class Animal { }\nclass Dog : Animal { }\nvoid Kennel()\n{\n    Animal[] pack = new Dog[2];\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2330");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class Animal { }\nclass Dog : Animal { }\nvoid Kennel()\n{\n    Dog[] pack = new Dog[2];\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2330").is_empty());
}

#[test]
fn s3215_flags_interface_casts_to_concrete_types() {
    let violating = analyze_default(
        "interface IGreeter\n{\n    void Greet();\n}\nclass Greeter : IGreeter\n{\n    public void Greet() { }\n}\nvoid Make()\n{\n    IGreeter g = null;\n    var c = (Greeter)g;\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3215");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 12);

    let clean = analyze_default(
        "interface IGreeter\n{\n    void Greet();\n}\nclass Greeter : IGreeter\n{\n    public void Greet() { }\n}\nvoid Make()\n{\n    IGreeter g = null;\n    g.Greet();\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3215").is_empty());
}

#[test]
fn s2234_flags_swapped_argument_order() {
    let violating = analyze_default(
        "class Calc\n{\n    public double Divide(double dividend, double divisor)\n    {\n        return dividend / divisor;\n    }\n    public void Quotient(double divisor, double dividend)\n    {\n        var ratio = Divide(divisor, dividend);\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2234");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 9);

    let clean = analyze_default(
        "class Calc\n{\n    public double Divide(double dividend, double divisor)\n    {\n        return dividend / divisor;\n    }\n    public void Quotient(double divisor, double dividend)\n    {\n        var ratio = Divide(dividend, divisor);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2234").is_empty());
}

#[test]
fn s3254_flags_arguments_duplicating_defaults() {
    let violating = analyze_default(
        "class Sender\n{\n    public void Send(string body, int retries = 3)\n    {\n    }\n    public void Deliver()\n    {\n        Send(\"hello\", 3);\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3254");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 8);

    let clean = analyze_default(
        "class Sender\n{\n    public void Send(string body, int retries = 3)\n    {\n    }\n    public void Deliver()\n    {\n        Send(\"hello\", 5);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3254").is_empty());
}

#[test]
fn s3220_flags_ambiguous_params_overload_calls() {
    let violating = analyze_default(
        "class Writer\n{\n    public void Write(string head, params object[] lines)\n    {\n    }\n    public void Write(object first, object second, object third)\n    {\n    }\n    public void Flush()\n    {\n        Write(\"\", null, null);\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3220");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 11);

    let clean = analyze_default(
        "class Writer\n{\n    public void Write(string head, params object[] lines)\n    {\n    }\n    public void Write(object first, object second, object third)\n    {\n    }\n    public void Flush()\n    {\n        Write(\"a\", \"b\");\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3220").is_empty());
}

#[test]
fn s2930_flags_undisposed_disposable_locals() {
    let violating = analyze_default(
        "class Importer\n{\n    public int CountRows()\n    {\n        FileStream stream = new FileStream(\"data.bin\", FileMode.Open);\n        return 1;\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2930");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let disposed = analyze_default(
        "class Importer\n{\n    public int CountRows()\n    {\n        FileStream stream = new FileStream(\"data.bin\", FileMode.Open);\n        stream.Dispose();\n        return 1;\n    }\n}\n",
    );
    assert!(with_key(&disposed, "csharpsquid:S2930").is_empty());

    let enclosed = analyze_default(
        "class Importer\n{\n    public int CountRows()\n    {\n        using (var stream = new FileStream(\"data.bin\", FileMode.Open))\n        {\n            return 1;\n        }\n    }\n}\n",
    );
    assert!(with_key(&enclosed, "csharpsquid:S2930").is_empty());
}

#[test]
fn s2931_flags_disposable_members_without_interface() {
    let violating =
        analyze_default("class Cache\n{\n    private FileStream stream = new FileStream();\n}\n");
    let flagged = with_key(&violating, "csharpsquid:S2931");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    let clean =
        analyze_default("class Cache : IDisposable\n{\n    private FileStream stream;\n}\n");
    assert!(with_key(&clean, "csharpsquid:S2931").is_empty());
}

#[test]
fn s2952_flags_fields_disposed_outside_dispose() {
    let violating = analyze_default(
        "class Worker : IDisposable\n{\n    private FileStream stream;\n    public void CleanUp()\n    {\n        stream.Dispose();\n    }\n    public void Dispose() { }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2952");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);

    let clean = analyze_default(
        "class Worker : IDisposable\n{\n    private FileStream stream;\n    public void Dispose()\n    {\n        stream.Dispose();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2952").is_empty());
}

#[test]
fn s2934_flags_property_writes_on_readonly_generic_fields() {
    let violating = analyze_default(
        "class Box<T>\n{\n    private readonly T value;\n    public void Reset()\n    {\n        value.Count = 0;\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2934");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);

    let clean = analyze_default(
        "class Box<T>\n    where T : class\n{\n    private readonly T value;\n    public void Reset()\n    {\n        value.Count = 0;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2934").is_empty());
}

#[test]
fn s5766_flags_serializable_without_deserialization_validation() {
    let violating =
        analyze_default("[Serializable]\nclass Session\n{\n    public string User;\n}\n");
    let flagged = with_key(&violating, "csharpsquid:S5766");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 2);

    let clean = analyze_default(
        "[Serializable]\nclass Session\n{\n    public string User;\n    [OnDeserialized]\n    public void Validate(StreamingContext context)\n    {\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S5766").is_empty());
}

#[test]
fn s6797_flags_unsupported_query_parameter_types() {
    let violating = analyze_default(
        "class Filters\n{\n    [SupplyParameterFromQuery]\n    public List<int> Pages { get; set; }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S6797");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let clean = analyze_default(
        "class Filters\n{\n    [SupplyParameterFromQuery]\n    public int Pages { get; set; }\n    [SupplyParameterFromQuery]\n    public Guid[] Ids { get; set; }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6797").is_empty());
}

#[test]
fn s6800_flags_parameter_types_contradicting_route_constraints() {
    let violating = analyze_default(
        "class OrderPage\n{\n    [Parameter]\n    public long Id { get; set; }\n    public void Template()\n    {\n        var path = \"/order/{id:int}\";\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S6800");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let clean = analyze_default(
        "class OrderPage\n{\n    [Parameter]\n    public int Id { get; set; }\n    public void Template()\n    {\n        var path = \"/order/{id:int}\";\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6800").is_empty());
}

#[test]
fn s6424_flags_properties_on_used_durable_entity_interfaces() {
    let violating = analyze_default(
        "interface IInventoryEntity\n{\n    int Count { get; }\n}\nclass C\n{\n    void M(IDurableEntityClient client)\n    {\n        client.SignalEntityAsync<IInventoryEntity>();\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S6424");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 9);

    let clean = analyze_default(
        "interface IInventoryEntity\n{\n    void Restock(int count);\n}\nclass C\n{\n    void M(IDurableEntityClient client)\n    {\n        client.SignalEntityAsync<IInventoryEntity>();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6424").is_empty());
}

#[test]
fn s6960_flags_mixed_responsibility_controllers() {
    let violating = analyze_default(
        "class DashboardController\n{\n    private readonly IUserService users;\n    private readonly IAuditService audit;\n    private readonly IReportService reports;\n    public void List() { }\n    public void Show() { }\n    public void Create() { }\n    public void Edit() { }\n    public void Remove() { }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S6960");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    let clean = analyze_default(
        "class DashboardController\n{\n    private readonly IUserService users;\n    private readonly IAuditService audit;\n    private readonly IReportService reports;\n    public void List() { }\n    public void Show() { }\n    public void Create() { }\n    public void Edit() { }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6960").is_empty());
}

#[test]
fn s4039_flags_calls_to_explicit_interface_implementations() {
    let violating = analyze_default(
        "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run()\n    {\n        Greet();\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S4039");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    public void Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run()\n    {\n        Greet();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4039").is_empty());
}

#[test]
fn s4347_flags_constant_seeded_generators() {
    let violating = analyze_default("var rng = new Random(1234);\nvar next = rng.Next();\n");
    let flagged = with_key(&violating, "csharpsquid:S4347");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    let clean = analyze_default("var rng2 = new Random();\nrng2.Next();\n");
    assert!(with_key(&clean, "csharpsquid:S4347").is_empty());
}

#[test]
fn s7130_flags_first_or_default_on_known_non_empty_collections() {
    let violating = analyze_default(
        "void Register()\n{\n    var ids = new List<int>();\n    ids.Add(1);\n    var first = ids.FirstOrDefault();\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S7130");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "void Register()\n{\n    var ids = new List<int>();\n    var first = ids.FirstOrDefault();\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S7130").is_empty());
}
