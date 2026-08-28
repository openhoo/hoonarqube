public class S3876Good
{
    public int this[long offset]
    {
        get { return 0; }
    }

    public int this[string key]
    {
        get { return 1; }
    }

    public int this[System.String name, char digit]
    {
        get { return 2; }
    }
}
