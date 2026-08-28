using Microsoft.AspNetCore.Mvc;

[Route("legacy")]
public class LegacyBridge : Controller
{
    [HttpGet("/bridge/status")]
    public void Status()
    {
    }

    [Route("/bridge/reload")]
    public void Reload()
    {
    }
}
