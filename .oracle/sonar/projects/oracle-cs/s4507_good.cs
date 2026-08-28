// S4507 good: diagnostics disabled or neutral in shipped strings.
namespace Oracle.S4507
{
    internal class DebuggingLeftEnabledGood
    {
        public string WebConfig() =>
            "<customErrors mode=\"RemoteOnly\" />"; // errors stay server-side

        public string CompilerOptions => "debug=false";

        public string BuildScript() => "dotnet build -c Release";
    }
}
