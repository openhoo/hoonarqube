public class Sample
{
    public double Adjust(double value)
    {
        if (value < 0.5)
        {
            return value * 2;
        }

        return System.Math.Abs(value - 0.1) < 0.001 ? 0 : value / 3;
    }
}
