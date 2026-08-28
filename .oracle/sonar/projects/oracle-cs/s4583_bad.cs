public class Dispatcher
{
    public delegate int Work(string input);

    public void Dispatch(Work work)
    {
        System.IAsyncResult pending = work.BeginInvoke("a", null, null);
        System.Console.WriteLine(pending.IsCompleted);
    }
}
