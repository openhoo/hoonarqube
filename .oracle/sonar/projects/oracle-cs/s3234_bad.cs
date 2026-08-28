public sealed class Resource
{
    public void Close()
    {
        System.GC.SuppressFinalize(this);
    }
}
