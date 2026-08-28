public class Suite
{
    [NUnit.Framework.Test]
    [NUnit.Framework.Ignore]
    public void Untested()
    {
        Probe();
    }

    private static void Probe()
    {
    }
}
