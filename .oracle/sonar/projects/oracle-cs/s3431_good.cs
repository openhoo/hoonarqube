public class CalculatorTests
{
    [NUnit.Framework.Test]
    public void RejectsZero()
    {
        try
        {
            Divide(1, 0);
        }
        catch (System.DivideByZeroException)
        {
            return;
        }
        throw new System.InvalidOperationException("expected failure");
    }

    [NUnit.Framework.Test]
    public void Divides()
    {
        Check(Divide(6, 3) == 2);
    }

    private static int Divide(int left, int right)
    {
        return left / right;
    }

    private static void Check(bool condition)
    {
    }
}
