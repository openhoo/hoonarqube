public class Sample
{
    public bool Check(int first)
    {
        int remainder = first % 4;
        bool small = first % 2 < 2 && remainder >= 0;
        return small;
    }
}
