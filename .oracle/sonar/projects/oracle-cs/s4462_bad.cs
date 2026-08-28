public class Sample
{
    public int Read(System.Threading.Tasks.Task<int> task)
    {
        task.Wait();
        return task.Result;
    }

    public string Drain(System.Threading.Tasks.Task<string> task)
    {
        return task.GetAwaiter().GetResult();
    }
}
