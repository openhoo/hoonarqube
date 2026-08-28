public class Vector : IEquatable<Vector>
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

internal sealed class Metric : IEquatable<Metric>
{
    public bool Equals(Metric other)
    {
        return other is not null && GetHashCode() == other.GetHashCode();
    }
}
