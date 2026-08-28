[Route("things/api")]
public class ThingWriter
{
    [HttpPut(@"things\v1\save")]
    public void Save()
    {
    }

    [HttpPost("things\\v1\\bulk")]
    public void Bulk()
    {
    }
}
