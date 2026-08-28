public class Sample
{
    public int Score(int value, bool flag)
    {
        var total = (int?)value ?? 0;
        var steps = new[] { 1, 2 };
        for (var index = 0; index < 4; index++)
        {
            if (total > 0 && flag)
            {
                total++;
            }
            if (total < 0 || !flag)
            {
                total--;
            }
            if (total == 42)
            {
                total = 0;
            }
            while (total > 100)
            {
                total -= 25;
            }
            total += total > 50 ? 1 : -1;
        }
        foreach (var item in steps)
        {
            total += item;
        }
        do
        {
            total++;
        }
        while (total < 3);
        return total;
    }
}
