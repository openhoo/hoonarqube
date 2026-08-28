public class Sample
{
    public int Evaluate(int value, bool flag)
    {
        var result = 0;
        if (value > 0)
        {
            if (flag)
            {
                for (var index = 0; index < 3; index++)
                {
                    while (result < value)
                    {
                        if (index % 2 == 0)
                        {
                            result++;
                        }
                        else if (value == 7 || value == 9)
                        {
                            result--;
                        }
                    }
                }
            }
        }
        return result;
    }
}
