public class Settings
{
    private static readonly string Root;

    private static int Fallback;

    static Settings()
    {
        Root = "/";
        Fallback = -1;
    }
}
