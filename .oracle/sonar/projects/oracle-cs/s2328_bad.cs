public class Stamp
{
    private int counter;
    private readonly int seed;

    public override int GetHashCode()
    {
        return counter * 31 + seed;
    }

    public void Tick()
    {
        counter = counter + 1;
    }
}

public class Gauge
{
    private int reading;

    public override int GetHashCode()
    {
        return reading.GetHashCode();
    }
}
