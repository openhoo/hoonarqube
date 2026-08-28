using Microsoft.AspNetCore.Mvc;

public class PersonController : Controller
{
    public IActionResult Index() => View();

    [HttpGet(template: "{sortBy}/{direction}")] // S6934
    [ProducesResponseType(typeof(object), 200)]
    public IActionResult List() => View();
}
