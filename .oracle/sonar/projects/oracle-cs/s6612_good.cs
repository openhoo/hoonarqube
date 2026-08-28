public class Cache
{
    public int Bump(System.Collections.Concurrent.ConcurrentDictionary<int, int> map)
    {
        map.GetOrAdd(1, key => 42);
        return map.AddOrUpdate(1, key => 1, (key, old) => old + 1);
    }
}
