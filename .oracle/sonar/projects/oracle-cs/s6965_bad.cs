using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[Route("api")]
public class CustomersController : Controller
{
    [Route("Customer")] // S6965
    public async Task<IResult> ChangeCustomer(object data)
    {
        await Task.CompletedTask;
        return Results.Ok();
    }

    [Route("Customer")] // S6965
    public async Task<string> GetCustomers()
    {
        await Task.CompletedTask;
        return "all";
    }
}
