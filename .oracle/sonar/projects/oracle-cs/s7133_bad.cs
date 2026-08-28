public class Session
{
    private readonly object gate = new object();

    public void Lock()
    {
        System.Threading.Monitor.Enter(gate);
        Work();
    }

    private void Work()
    {
    }
}
