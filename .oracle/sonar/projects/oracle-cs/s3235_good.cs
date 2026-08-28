public class Sample
{
    public int Value()
    {
        return 42;
    }

    public int Sum(int left, int right)
    {
        return left + right;
    }

    public int DoubledSum(int left, int right)
    {
        return (left + right) * 2;
    }

    public void Print()
    {
        System.Console.WriteLine(Sum(1, 2));
    }
}
