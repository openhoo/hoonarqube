public class S2701Bad
{
    public void Check()
    {
        NUnit.Framework.Assert.IsTrue(true);
        NUnit.Framework.Assert.IsFalse(false);
    }
}
