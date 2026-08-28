public class Worker
{
    public void Wait()
    {
        System.Threading.Thread.Sleep(100);
    }

    [NUnit.Framework.Test]
    public void SignalsPromptly()
    {
        Waiter.Ready();
    }
}

public class Waiter
{
    public static void Ready()
    {
    }
}
