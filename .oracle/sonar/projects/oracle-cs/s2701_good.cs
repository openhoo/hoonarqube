public class S2701Good
{
    public void Check(bool ready)
    {
        NUnit.Framework.Assert.IsTrue(ready);
        NUnit.Framework.Assert.IsFalse(ready, "because");
    }
}
