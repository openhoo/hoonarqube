using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("fetch")]
public class FetcherController : ControllerBase
{
    private readonly IHttpClientFactory factory;

    public FetcherController(IHttpClientFactory factory) => this.factory = factory;

    [HttpGet]
    [ProducesResponseType(typeof(string), 200)]
    public async Task<string> Pull()
    {
        var client = factory.CreateClient();
        return await client.GetStringAsync("https://example.com");
    }
}
