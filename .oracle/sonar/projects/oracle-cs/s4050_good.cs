public class Meter
{
    private readonly int units;

    public static bool operator ==(Meter left, Meter right)
    {
        return left.units == right.units;
    }

    public static bool operator !=(Meter left, Meter right)
    {
        return left.units != right.units;
    }

    public override bool Equals(object obj)
    {
        return obj is Meter other && units == other.units;
    }

    public override int GetHashCode()
    {
        return units.GetHashCode();
    }
}
