using System.Diagnostics.CodeAnalysis;

public struct Coordinates
{
    public int X { get; }
    public int Y { get; }

    [ExcludeFromCodeCoverage(Justification = "Generated equality member")]
    public override bool Equals(object? value) =>
        value is Coordinates coordinates && X == coordinates.X && Y == coordinates.Y;

    [ExcludeFromCodeCoverage(Justification = "Generated equality member")]
    public override int GetHashCode() => System.HashCode.Combine(X, Y);
}
