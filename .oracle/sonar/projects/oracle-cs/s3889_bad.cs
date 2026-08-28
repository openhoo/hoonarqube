public class ThreadFreezer
{
    public void Freeze(System.Threading.Thread worker)
    {
        worker.Suspend();
        System.Threading.Thread.CurrentThread.Resume();
    }
}
