public class Limits
{
    public long MaxRequestBodySize { get; set; }
    public long MaxRequestBodyLength { get; set; }
    public long MultipartBodyLengthLimit { get; set; }
    public long FormSize { get; set; }
}

public class Sample
{
    private readonly Limits _limits = new Limits();

    public void Configure()
    {
        _limits.MaxRequestBodySize = 53687091200;
        _limits.MaxRequestBodyLength = 16777216;
        _limits.MultipartBodyLengthLimit = 20971520;
        _limits.FormSize = 10485760;
    }
}
