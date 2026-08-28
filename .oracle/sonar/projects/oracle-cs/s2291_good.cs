public class S2291Good
{
    public int Total(int[] values)
    {
        checked
        {
            return values.Sum();
        }
    }

    public int Plain(int[] values)
    {
        unchecked
        {
            return values.Length + values.Max();
        }
    }
}
