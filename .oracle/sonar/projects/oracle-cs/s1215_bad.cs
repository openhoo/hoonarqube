public class CacheJanitor
{
    public void Clean()
    {
        GC.Collect();
        System.GC.Collect(2);
    }
}
