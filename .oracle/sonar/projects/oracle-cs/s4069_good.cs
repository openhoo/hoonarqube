public struct Range
{
    private readonly int start;

    public static bool operator <(Range a, Range b)
    {
        return a.start < b.start;
    }

    public static bool operator >(Range a, Range b)
    {
        return a.start > b.start;
    }

    public int CompareTo(Range other)
    {
        return start.CompareTo(other.start);
    }
}
