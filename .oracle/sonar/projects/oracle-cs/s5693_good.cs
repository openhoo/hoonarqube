public class SafeLimits
{
    public long MaxRequestBodySize { get; set; }
    public long MultipartBodyLengthLimit { get; set; }
    public long FormSize { get; set; }
    public long UnrelatedBufferLimit { get; set; }
}

public class Sample
{
    private readonly SafeLimits _limits = new SafeLimits();

    public void Configure()
    {
        _limits.MaxRequestBodySize = 8388608;
        _limits.MultipartBodyLengthLimit = 1048576;
        _limits.FormSize = 4096;
        _limits.MaxRequestBodySize += 9000000;
        _limits.FormSize = long.MaxValue;
        _limits.UnrelatedBufferLimit = 107374182400;
    }
}
