public class Sample
{
    public static System.Collections.Generic.IEnumerable<int> Pages(int count)
    {
        if (count < 0)
        {
            throw new System.ArgumentOutOfRangeException(nameof(count));
        }
        yield return count;
    }
}
