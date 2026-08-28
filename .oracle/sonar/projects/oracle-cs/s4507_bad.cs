// S4507 bad: debug switches left on in shipped configuration strings.
namespace Oracle.S4507
{
    internal class DebuggingLeftEnabledBad
    {
        public string WebConfig() =>
            "<customErrors mode=\"Off\" />"; // S4507

        public string CompilerOptions => "debug=true;verbose"; // S4507

        public string BuildScript() =>
            "set debug=true & dotnet build"; // S4507

        public string RemoteOnly() => "<customErrors mode=\"RemoteOnly\" />"; // ok
    }
}
