public class S1313Bad
{
    public System.Net.IPAddress Primary()
    {
        return System.Net.IPAddress.Parse("192.168.0.12");
    }

    public System.Net.IPAddress Secondary()
    {
        return System.Net.IPAddress.Parse("10.0.0.1");
    }
}
