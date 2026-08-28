public class Sample
{
    public bool Check(int first, int second)
    {
        bool even = first % 2 == 0;
        bool odd = second % 3 != 1;
        return even || odd;
    }
}
