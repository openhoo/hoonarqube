public class Sample
{
    public bool Check(int value, int bound)
    {
        bool within = value <= bound;
        bool above = value >= bound - 1;
        return within || above;
    }
}
