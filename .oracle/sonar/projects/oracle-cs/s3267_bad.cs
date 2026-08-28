public class Picker
{
    public void Gather(int[] items, System.Collections.Generic.List<int> picked)
    {
        foreach (var item in items)
        {
            if (item > 0)
            {
                picked.Add(item);
            }
        }
    }

    public void CollectEven(int[] items, System.Collections.Generic.List<int> picked)
    {
        foreach (var item in items)
        {
            if (item % 2 == 0)
            {
                picked.Add(item);
            }
        }
    }
}
