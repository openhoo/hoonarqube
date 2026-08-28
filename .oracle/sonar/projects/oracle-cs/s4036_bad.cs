public class Launcher
{
    public void RunTools()
    {
        System.Diagnostics.Process.Start("curl");
        System.Diagnostics.Process.Start("sh -c 'ls'");
    }
}
