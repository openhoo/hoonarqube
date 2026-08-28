public class S3415Good
{
    public void Check(int actual, int expected)
    {
        NUnit.Framework.Assert.AreEqual(expected, actual);
        NUnit.Framework.Assert.AreSame(actual, actual);
        NUnit.Framework.Assert.AreNotEqual(7, actual);
        NUnit.Framework.Assert.AreEqual(actual, Compute());
    }

    private int Compute()
    {
        return 7;
    }
}
