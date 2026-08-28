public class Sample
{
    public void Unpack(string zipPath, string target)
    {
        System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, target);
        var entry = default(System.IO.Compression.ZipArchiveEntry);
        entry.ExtractToFile(System.IO.Path.Combine(target, "entry.bin"));
        System.Console.WriteLine(zipPath.Length + target.Length);
    }
}
