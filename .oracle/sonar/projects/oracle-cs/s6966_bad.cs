using System.IO;
using System.Threading.Tasks;

public class Sample
{
    public async Task Read(Stream stream, byte[] buffer)
    {
        stream.Read(buffer, 0, 1024); // S6966
        File.ReadAllLines("path"); // S6966
        await Task.CompletedTask;
    }
}
