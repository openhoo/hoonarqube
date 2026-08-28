class S3237Good
{
    private int cached;
    private int backup;

    int Stored
    {
        get { return cached; }
        set { cached = value; }
    }

    int Forwarded
    {
        set { backup = value + 1; }
    }
}
