public class Configuration
{
    private string seed = "ready";

    public string Seed
    {
        get { return seed; }
        set { seed = value; }
    }

    public string Guarded
    {
        get => seed;
        set => throw new System.InvalidOperationException("read only");
    }
}
