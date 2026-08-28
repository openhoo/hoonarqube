using System.Net.Http;
using System.Threading.Tasks;

public class Runner
{
    public async Task<HttpResponseMessage> Run(HttpClient client, string url)
    {
        return await client.GetAsync(url); // S3216
    }
}
