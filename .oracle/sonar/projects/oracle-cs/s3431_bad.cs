public class CalculatorTests
{
    [NUnit.Framework.ExpectedException(typeof(System.ArgumentException))]
    [NUnit.Framework.Test]
    public void RejectsNegative()
    {
        var actual = Divide(1, 0);
        System.Console.WriteLine(actual);
    }

    [NUnit.Framework.Test]
    [NUnit.Framework.ExpectedException(typeof(System.InvalidOperationException))]
    public void RejectsNull()
    {
        var actual = Divide(0, 0);
        System.Console.WriteLine(actual);
    }

    private static int Divide(int left, int right)
    {
        return left / right;
    }
}
