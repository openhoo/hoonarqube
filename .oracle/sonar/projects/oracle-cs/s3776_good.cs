public class Sample
{
    public int Evaluate(int value, bool flag)
    {
        var result = value;
        if (flag)
        {
            result++;
        }
        return result;
    }
}
