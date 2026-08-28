using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[Route("api")]
public class CustomersController : Controller
{
    [HttpPost("Customer")]
    [ProducesResponseType(typeof(object), 200)]
    public async Task<IResult> ChangeCustomer(object data)
    {
        await Task.CompletedTask;
        return Results.Ok();
    }

    [HttpGet("Customer")]
    [ProducesResponseType(typeof(string), 200)]
    public async Task<string> GetCustomers()
    {
        await Task.CompletedTask;
        return "all";
    }
}
