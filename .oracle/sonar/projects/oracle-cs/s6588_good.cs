public class EpochMath
{
    private static readonly System.DateTimeOffset Epoch = System.DateTimeOffset.UnixEpoch;

    public System.DateTime ReleaseDay()
    {
        return new System.DateTime(2024, 1, 1);
    }
}
