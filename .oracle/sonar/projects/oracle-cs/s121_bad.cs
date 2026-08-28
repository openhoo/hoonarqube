public class Sample
{
    public int Pick(int value)
    {
        if (value > 0)
            return 1;
        for (var index = 0; index < 3; index++)
            value += index;
        while (value < 0)
            value++;
        return value;
    }
}
