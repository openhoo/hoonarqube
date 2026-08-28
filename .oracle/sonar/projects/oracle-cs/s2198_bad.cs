public class Sample
{
    public bool Check(float value)
    {
        bool always = value <= double.MaxValue; // S2198
        bool never = value > double.MaxValue; // S2198
        return always || never;
    }
}
