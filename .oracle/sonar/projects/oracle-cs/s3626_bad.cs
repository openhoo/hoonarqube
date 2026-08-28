public class Sample
{
    public int Sum(System.Collections.Generic.List<int> items)
    {
        int total = 0;
        foreach (int item in items)
        {
            total += item;
            continue;
        }

        while (total > 0)
        {
            total -= 1;
            break;
        }

        return total;
    }
}
