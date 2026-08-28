public class Sample
{
    public bool Check(double value)
    {
        if (double.IsNaN(value))
        {
            return true;
        }

        return value < double.PositiveInfinity;
    }
}
