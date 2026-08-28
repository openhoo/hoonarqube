// S5332 bad: clear-text http/ws endpoints without exemptions.
namespace Oracle.S5332
{
    internal class ClearTextProtocolsBad
    {
        private const string ApiBase = "http://api.example.com/v1"; // S5332

        private const string SocketUrl = "ws://chat.example.com/socket"; // S5332

        public string HealthProbe() => "http://internal.corp/health"; // S5332
    }
}
