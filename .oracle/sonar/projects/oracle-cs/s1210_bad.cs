public class Temp : System.IComparable<Temp>
{
    public int value;

    public int CompareTo(Temp other)
    {
        return value.CompareTo(other.value);
    }

    public override bool Equals(object obj)
    {
        return obj is Temp other && value == other.value;
    }
}

public struct Level : System.IComparable<Level>
{
    public int rank;

    public int CompareTo(Level other)
    {
        return rank.CompareTo(other.rank);
    }
}
