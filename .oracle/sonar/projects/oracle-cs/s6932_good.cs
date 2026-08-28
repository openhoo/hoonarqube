using Microsoft.AspNetCore.Mvc;

public class BoundReader : Controller
{
    public IActionResult Post([FromForm] string name, [FromQuery] string locale)
    {
        return Ok(name + locale);
    }
}
