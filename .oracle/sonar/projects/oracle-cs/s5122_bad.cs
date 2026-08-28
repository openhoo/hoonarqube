// S5122 bad: reflecting any origin in CORS.
using Microsoft.AspNetCore.Cors.Infrastructure;

namespace Oracle.S5122
{
    internal class CorsSetupBad
    {
        public void Configure(CorsPolicyBuilder builder)
        {
            builder.AllowAnyOrigin(); // S5122
        }

        public string RawHeader() => "Access-Control-Allow-Origin: *"; // S5122

        public const string OwinHeader = "access-control-allow-origin,*"; // S5122
    }
}
