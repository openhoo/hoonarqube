using Microsoft.AspNetCore.Mvc;

[Route("people")]
public class PersonController : Controller
{
    public IActionResult Index() => View();

    [HttpGet(template: "{sortBy}/{direction}")]
    [ProducesResponseType(typeof(object), 200)]
    public IActionResult List() => View();
}
