// S5122 good: origins restricted to trusted hosts.
using System.Collections.Generic;
using Microsoft.AspNetCore.Cors.Infrastructure;

namespace Oracle.S5122
{
    internal class CorsSetupGood
    {
        private static readonly List<string> TrustedOrigins = new()
        {
            "https://portal.example.com",
            "https://admin.example.com",
        };

        public void Configure(CorsPolicyBuilder builder)
        {
            builder.WithOrigins(TrustedOrigins.ToArray())
                .AllowCredentials();
        }

        public string RawHeader() => "Access-Control-Allow-Origin: https://portal.example.com";
    }
}
