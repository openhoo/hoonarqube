public class ZoneResolver
{
    public System.TimeZoneInfo Local()
    {
        return System.TimeZoneInfo.Local;
    }

    public void Reset()
    {
        System.TimeZoneInfo.ClearCachedData();
    }
}
