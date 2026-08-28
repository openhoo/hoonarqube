class Cache : IDisposable
{
    private FileStream stream;

    public SqlConnection Connection { get; set; }

    public void Dispose()
    {
        stream?.Dispose();
        Connection?.Dispose();
    }
}
