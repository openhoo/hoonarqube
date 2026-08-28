public class Sample
{
    public int Safe()
    {
        checked
        {
            var maximum = int.MaxValue;
            return maximum + 1;
        }
    }
}
