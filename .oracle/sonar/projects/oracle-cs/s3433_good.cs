[NUnit.Framework.TestFixture]
public class S3433Good
{
    [NUnit.Framework.Test]
    public void Works()
    {
    }

    [NUnit.Framework.Test]
    public Task<int> Fetch()
    {
        return Task.FromResult(1);
    }
}
