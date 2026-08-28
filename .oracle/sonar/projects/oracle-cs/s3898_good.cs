public struct Point : System.IEquatable<Point>
{
    public int X;
    public int Y;

    public bool Equals(Point other)
    {
        return X == other.X && Y == other.Y;
    }
}

public class RefKind
{
    public int W;
}
