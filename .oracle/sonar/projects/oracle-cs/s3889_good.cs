public class ThreadRunner
{
    public void Run(System.Threading.Thread worker)
    {
        System.Threading.Thread.Sleep(1);
        worker.Interrupt();
        Start(worker);
    }

    private static void Start(System.Threading.Thread worker)
    {
        worker.Start();
    }
}
