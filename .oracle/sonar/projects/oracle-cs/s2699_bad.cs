public class S2699Bad
{
    [NUnit.Framework.Test]
    public void First()
    {
        System.Console.WriteLine("first");
        Prepare();
    }

    [NUnit.Framework.Test]
    public void Second()
    {
        System.Console.WriteLine("second");
    }
}
