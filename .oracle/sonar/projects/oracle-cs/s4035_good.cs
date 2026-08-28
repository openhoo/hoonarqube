internal sealed class Vector : IEquatable<Vector>
{
    public int X { get; }

    public int Y { get; }

    public Vector(int x, int y)
    {
        X = x;
        Y = y;
    }

    public bool Equals(Vector other)
    {
        return X == other.X && Y == other.Y;
    }
}

internal abstract class Metric : IEquatable<Metric>
{
    public abstract bool Equals(Metric other);
}

internal class Reading : IComparable<Reading>
{
    public int Value { get; set; }

    public int CompareTo(Reading other)
    {
        return Value - other.Value;
    }
}
