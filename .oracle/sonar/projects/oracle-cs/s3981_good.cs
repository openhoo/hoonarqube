public class Sample
{
    public int Room(int[] items, int size)
    {
        int roomy = items.Length < 10 ? 1 : 0;
        int plain = size < -1 ? 1 : 0;
        return roomy + plain;
    }
}
