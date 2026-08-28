public class Settings
{
    private const string Root = "/";

    private static int Fallback = -1;

    private static string computed;

    public string Describe()
    {
        return computed ?? Root;
    }
}
