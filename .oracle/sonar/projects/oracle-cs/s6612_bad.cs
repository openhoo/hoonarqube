public class Cache
{
    public int Bump(System.Collections.Concurrent.ConcurrentDictionary<int, int> map, int key)
    {
        return map.GetOrAdd(key, _ => key + 42); // S6612
    }
}
