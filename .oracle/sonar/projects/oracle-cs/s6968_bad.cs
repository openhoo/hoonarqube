using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("widgets")]
public class WidgetApi : ControllerBase
{
    [HttpGet("find")]
    public IActionResult Find() => Ok(42); // S6968
}
