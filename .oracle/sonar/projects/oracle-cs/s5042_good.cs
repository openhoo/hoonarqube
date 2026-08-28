public class Sample
{
    public void BoundedUnpack(string zipPath, string target)
    {
        using var archive = System.IO.Compression.ZipFile.OpenRead(zipPath);
        foreach (var entry in archive.Entries)
        {
            var destination = System.IO.Path.Combine(target, entry.FullName);
            using var input = entry.Open();
            using var output = System.IO.File.Create(destination);
            input.CopyTo(output);
        }
    }

    public async System.Threading.Tasks.Task ModernAsync(System.IO.Compression.ZipArchive archive, string dir)
    {
        await archive.ExtractToDirectoryAsync(dir);
    }
}
