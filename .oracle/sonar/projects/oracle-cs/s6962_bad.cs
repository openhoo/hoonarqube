using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("fetch")]
public class FetcherController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(typeof(string), 200)]
    public async Task<string> Pull()
    {
        using var client = new HttpClient(); // S6962
        return await client.GetStringAsync("https://example.com");
    }
}
