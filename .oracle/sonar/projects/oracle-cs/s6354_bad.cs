public class Clock
{
    public string Stamp()
    {
        return DateTime.Now.ToString("O");
    }

    public string StampUtc()
    {
        return DateTime.UtcNow.ToString("O");
    }
}
