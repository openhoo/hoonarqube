class S3237Bad
{
    private int cached;
    private int backup;

    int Broken
    {
        get { return cached; }
        set { cached = backup; }
    }
}
