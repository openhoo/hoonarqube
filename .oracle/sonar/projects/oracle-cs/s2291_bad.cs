public class S2291Bad
{
    public int Total(int[] values, int[] extra)
    {
        unchecked
        {
            return values.Sum() + extra.Sum();
        }
    }

    public int Weighted(int[] values)
    {
        unchecked
        {
            return values.Sum(value => value * 2);
        }
    }
}
