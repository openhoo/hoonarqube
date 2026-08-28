public class Meter
{
    public static Meter operator +(Meter left, Meter right)
    {
        return new Meter(left.units + right.units);
    }

    private readonly int units;

    private Meter(int units)
    {
        this.units = units;
    }
}

public class Gauge
{
    private readonly int units;

    public static bool operator ==(Gauge left, Gauge right)
    {
        return left.units == right.units;
    }

    public static bool operator !=(Gauge left, Gauge right)
    {
        return left.units != right.units;
    }
}
