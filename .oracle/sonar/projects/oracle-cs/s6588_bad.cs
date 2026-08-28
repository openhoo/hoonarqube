public class EpochMath
{
    public System.DateTime EpochDate()
    {
        return new System.DateTime(1970, 1, 1);
    }

    public System.DateTime EpochUtc()
    {
        return new System.DateTime(1970, 1, 1, 0, 0, 0, System.DateTimeKind.Utc);
    }
}
