public class Sample
{
    public bool Check(double value)
    {
        bool exact = value == 0.1;
        bool reversed = 0.5 == value;
        bool suffixed = value != 1.5f;
        return exact || reversed || suffixed;
    }
}
