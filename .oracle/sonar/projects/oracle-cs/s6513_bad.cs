using System.Diagnostics.CodeAnalysis;

public struct Coordinates
{
    public int X { get; }
    public int Y { get; }

    [ExcludeFromCodeCoverage] // S6513
    public override bool Equals(object? value) =>
        value is Coordinates coordinates && X == coordinates.X && Y == coordinates.Y;

    [ExcludeFromCodeCoverage] // S6513
    public override int GetHashCode() => System.HashCode.Combine(X, Y);
}
