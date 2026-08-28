using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

public class SecurityHeaders
{
    public Task InvokeAsync(HttpContext context)
    {
        context.Response.Headers.ContentSecurityPolicy = "script-src 'self';";
        return Task.CompletedTask;
    }
}
