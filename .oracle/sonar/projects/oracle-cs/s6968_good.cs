using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("widgets")]
public class WidgetApi : ControllerBase
{
    [HttpGet("find")]
    [ProducesResponseType(typeof(int), StatusCodes.Status200OK)]
    public IActionResult Find() => Ok(42);
}
