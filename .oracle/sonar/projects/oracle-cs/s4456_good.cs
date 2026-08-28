public class Sample
{
    public static System.Collections.Generic.IEnumerable<int> Pages(int count)
    {
        if (count < 0)
        {
            throw new System.ArgumentOutOfRangeException(nameof(count));
        }
        return Enumerate(count);
    }

    private static System.Collections.Generic.IEnumerable<int> Enumerate(int count)
    {
        yield return count;
        if (count > 100)
        {
            yield break;
        }
    }
}
