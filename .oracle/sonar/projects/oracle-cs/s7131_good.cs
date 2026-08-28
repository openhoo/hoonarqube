public class CacheGuard
{
    private readonly System.Threading.ReaderWriterLock guard = new System.Threading.ReaderWriterLock();

    public string Read()
    {
        guard.AcquireReaderLock(1000);
        try
        {
            return "cached";
        }
        finally
        {
            guard.ReleaseReaderLock();
        }
    }
}
