public class Stamps
{
    public System.DateTime ExplicitUtc()
    {
        return new System.DateTime(2024, 4, 1, 12, 0, 0, System.DateTimeKind.Utc);
    }

    public System.DateTime ExplicitLocal()
    {
        return new System.DateTime(2024, 4, 1, 0, 0, 0, System.DateTimeKind.Local);
    }
}
