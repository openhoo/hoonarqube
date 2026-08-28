using Microsoft.AspNetCore.Mvc;

public class RawReader : Controller
{
    public IActionResult Post()
    {
        var name = Request.Form["name"]; // S6932
        var locale = Request.Query["locale"]; // S6932
        return Ok(name + locale);
    }
}
