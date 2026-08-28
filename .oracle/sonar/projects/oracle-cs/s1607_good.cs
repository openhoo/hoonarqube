public class Suite
{
    [NUnit.Framework.Test]
    public void Works()
    {
        Probe();
    }

    [NUnit.Framework.Test]
    public void AlsoWorks()
    {
        Probe();
    }

    private static void Probe()
    {
    }
}
