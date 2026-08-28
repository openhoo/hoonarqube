using TimeZoneConverter;

public class ZoneResolver
{
    public System.TimeZoneInfo Resolve()
    {
        var windowsZone = TZConvert.IanaToWindows("Asia/Tokyo");
        return TimeZoneInfo.FindSystemTimeZoneById(windowsZone); // S6575
    }
}
