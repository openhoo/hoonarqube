using System.IO;
using System.Threading.Tasks;

public class Sample
{
    public async Task Read(Stream stream, byte[] buffer)
    {
        await stream.ReadAsync(buffer);
        await File.ReadAllLinesAsync("path");
    }
}
