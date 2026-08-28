[Route("things")]
public class ThingWriter
{
    [HttpPut("things/save")]
    public void Save()
    {
    }

    [HttpPost("things/bulk")]
    public void Bulk()
    {
    }
}
