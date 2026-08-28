public class Sample
{
    public bool Check(double value)
    {
        bool a = value == double.NaN;
        bool b = float.NaN != value;
        return a || b;
    }
}
