public class Sample
{
    public int Pick(int value)
    {
        if (value > 0)
        {
            return 1;
        }
        else
        {
            return -1;
        }
    }

    public int Partial(bool flag)
    {
        if (flag)
        {
            return 1;
        }

        return 0;
    }
}
