public class Sample
{
    public void Fill(System.IO.Stream stream, byte[] buffer)
    {
        stream.Read(buffer, 0, buffer.Length);
    }
}
