using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

[Route("profiles")]
public class ProfilesController : Controller
{
    [HttpPost("profiles/save")]
    [ProducesResponseType(typeof(object), 200)]
    public IActionResult Save(ProfileInput input)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        return Ok(input.Name);
    }
}

public class ProfileInput
{
    [Required]
    public string Name { get; set; } = "";
}
