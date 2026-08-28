public class Session
{
    private readonly object gate = new object();

    public void Lock()
    {
        System.Threading.Monitor.Enter(gate);
        try
        {
            Work();
        }
        finally
        {
            System.Threading.Monitor.Exit(gate);
        }
    }

    private void Work()
    {
    }
}
