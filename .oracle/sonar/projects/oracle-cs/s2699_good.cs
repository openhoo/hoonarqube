public class S2699Good
{
    [NUnit.Framework.Test]
    public void UsesFluent()
    {
        var result = 2;
        NUnit.Framework.Assert.AreEqual(2, result);
    }

    [NUnit.Framework.Test]
    public void UsesAssert()
    {
        NUnit.Framework.Assert.AreEqual(2, Compute());
    }

    private int Compute()
    {
        return 2;
    }
}
