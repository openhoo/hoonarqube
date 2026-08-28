// S5332 good: encrypted endpoints plus exempted loopback/schema hosts.
namespace Oracle.S5332
{
    internal class ClearTextProtocolsGood
    {
        private const string ApiBase = "https://api.example.com/v1";

        private const string LoopbackHealth = "http://localhost:5000/health";

        private const string UnitHealth = "http://127.0.0.1:8080/ping";

        private const string XsdImport = "http://www.w3.org/2001/XMLSchema";

        private const string BindingNamespace = "http://schemas.microsoft.com/wcf/2005";
    }
}
