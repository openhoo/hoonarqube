public class Sample
{
    public int Score(int value, bool flag)
    {
        var total = value;
        if (flag)
        {
            total++;
        }
        for (var index = 0; index < 3; index++)
        {
            total += index;
        }
        return total;
    }
}
