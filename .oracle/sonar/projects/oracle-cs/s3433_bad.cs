[NUnit.Framework.TestFixture]
public class S3433Bad
{
    [NUnit.Framework.Test]
    public int Compute()
    {
        return 1;
    }

    [NUnit.Framework.Test]
    internal Task Load()
    {
        return Task.CompletedTask;
    }

    [NUnit.Framework.Test]
    public ValueTask Save()
    {
        return ValueTask.CompletedTask;
    }
}
