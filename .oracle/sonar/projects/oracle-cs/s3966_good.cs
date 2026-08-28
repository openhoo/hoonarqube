public class Sample
{
    public void Close(System.IO.Stream stream)
    {
        stream.Dispose();
        stream = System.IO.File.OpenRead("data.bin");
        stream.Dispose();
    }
}
