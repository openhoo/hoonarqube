class Worker
{
    private FileStream stream;

    public void Dispose()
    {
        stream.Dispose();
    }
}
