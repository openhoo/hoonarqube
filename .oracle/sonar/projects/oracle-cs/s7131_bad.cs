public class CacheGuard
{
    private readonly System.Threading.ReaderWriterLock guard = new System.Threading.ReaderWriterLock();

    public string Read()
    {
        guard.AcquireReaderLock(1000);
        return "cached";
    }

    public void Write()
    {
        guard.AcquireWriterLock(1000);
        guard.ReleaseWriterLock();
    }
}
