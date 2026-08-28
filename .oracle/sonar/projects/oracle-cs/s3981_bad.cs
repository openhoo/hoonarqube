public class Sample
{
    public int Room(System.Collections.Generic.List<int> list, int[] items)
    {
        int a = list.Count < -1 ? 1 : 0;
        int b = -2 >= items.Length ? 1 : 0;
        return a + b;
    }
}
