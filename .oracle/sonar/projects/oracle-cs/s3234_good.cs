public sealed class Resource
{
    ~Resource() { }

    public void Close()
    {
        System.GC.SuppressFinalize(this);
    }
}
