public class Worker : System.IDisposable
{
    private System.IO.FileStream stream;

    public void CleanUp()
    {
        stream.Dispose();
    }

    public void Dispose()
    {
    }
}
